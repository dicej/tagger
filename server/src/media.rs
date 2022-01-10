//! This module provides the [image] function, responsible for handling GET /image/.. requests, which may retrieve
//! either original media items or derived artifacts (e.g. thumbnails) for those items.  It also provides functions
//! and types useful for analyzing, resampling, reencoding, and deduplicating media items.

use {
    crate::warp_util::{HttpDate, HttpError, Ranges},
    anyhow::{anyhow, Error, Result},
    bytes::{Bytes, BytesMut},
    futures::{stream, Stream, StreamExt, TryStreamExt},
    http::{header, status::StatusCode, Response},
    hyper::Body,
    image::{imageops::FilterType, GenericImageView, ImageFormat, Rgba},
    mp4parse::{CodecType, MediaContext, SampleEntry, Track, TrackType},
    rexiv2::{Metadata as ExifMetadata, Orientation},
    sqlx::SqliteConnection,
    std::{
        collections::VecDeque,
        convert::{TryFrom, TryInto},
        fs::File,
        io::{Seek, SeekFrom, Write},
        mem,
        ops::DerefMut,
        path::{Path, PathBuf},
        time::Duration,
    },
    tagger_shared::{Size, Variant},
    tempfile::NamedTempFile,
    tokio::{
        fs::{self, File as AsyncFile},
        io::{AsyncRead, AsyncReadExt, AsyncSeekExt},
        process::Command,
        sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock},
        task,
    },
    tokio_util::codec::{BytesCodec, FramedRead},
};

/// Maximum bounding box for thumbnail images and videos
pub const SMALL_BOUNDS: (u32, u32) = (480, 320);

/// Maximum bounding box for high-resolution preview images and videos
pub const LARGE_BOUNDS: (u32, u32) = (1920, 1280);

/// Empirically derived quality setting used when encoding WEBP images
///
/// This provides a good tradeoff between file size and image quality, with no obvious artifacts in most cases.
const WEBP_QUALITY: f32 = 85.0;

/// Maximum length in hours:minutes:seconds of video thumbnails
///
/// The format of this string is what FFmpeg's "-to" option expects.
const VIDEO_PREVIEW_LENGTH_HMS: &str = "00:00:05";

/// Maximum absolute difference (averaged over each per-8-bit-color-channel of all pixels) permitted when comparing
/// two images in order to consider them duplicates of each other.
const MAX_AVERAGE_ABSOLUTE_DIFFERENCE: usize = 5;

/// Pair of a media item hash and one of the files where that item was found
pub struct ItemData {
    pub hash: String,
    pub file: FileData,
}

/// Metadata about a media item file
pub struct FileData {
    /// Filesystem path where the file can be found
    pub path: String,

    /// Offset from the beginning of the file where MPEG-4 data can be found
    ///
    /// This will be zero for MP4 files, non-zero for "motion photo" files, and `None` for images with no embedded
    /// videos.
    pub video_offset: Option<i64>,
}

/// Find and return `FileData` for one of the files where the item with the specified `hash` was found.
///
/// There may be more than one such file in the database; this function will pick one arbitrarily.
#[allow(clippy::eval_order_dependence)]
async fn file_data(conn: &mut SqliteConnection, hash: &str) -> Result<FileData> {
    if let (Some(path), Some(image)) = (
        sqlx::query!("SELECT path FROM paths WHERE hash = ?1 LIMIT 1", hash)
            .fetch_optional(&mut *conn)
            .await?,
        sqlx::query!(
            "SELECT video_offset FROM images WHERE hash = ?1 LIMIT 1",
            hash
        )
        .fetch_optional(&mut *conn)
        .await?,
    ) {
        Ok(FileData {
            path: path.path,
            video_offset: image.video_offset,
        })
    } else {
        Err(HttpError::from_slice(StatusCode::NOT_FOUND, "not found").into())
    }
}

/// Return true iff the specified `orientation` is a 90 degree rotation in any direction.
fn orthagonal(orientation: Orientation) -> bool {
    matches!(
        orientation,
        Orientation::Rotate90HorizontalFlip
            | Orientation::Rotate90
            | Orientation::Rotate90VerticalFlip
            | Orientation::Rotate270
    )
}

/// Calculate the resized dimensions for an image using the specified bounding box, preserving aspect ratio (to
/// within integer precision) and respecting `orientation`.
fn bound(
    (native_width, native_height): (u32, u32),
    (mut bound_width, mut bound_height): (u32, u32),
    orientation: Orientation,
) -> (u32, u32) {
    if orthagonal(orientation) {
        mem::swap(&mut bound_width, &mut bound_height);
    }

    if native_width * bound_height > bound_width * native_height {
        (bound_width, (native_height * bound_width) / native_width)
    } else {
        ((native_width * bound_height) / native_height, bound_height)
    }
}

/// Produce a still image from the first frame of the specified video.
async fn still_image(image_dir: &str, path: &str) -> Result<(Vec<u8>, ImageFormat)> {
    let full_path = [image_dir, path].iter().collect::<PathBuf>();

    let lowercase = path.to_lowercase();

    if lowercase.ends_with(".mp4") || lowercase.ends_with(".mov") {
        let output = Command::new("ffmpeg")
            .arg("-i")
            .arg(full_path)
            .arg("-ss")
            .arg("00:00:00")
            .arg("-frames:v")
            .arg("1")
            .arg("-f")
            .arg("singlejpeg")
            .arg("-")
            .output()
            .await?;

        if output.status.success() {
            Ok((output.stdout, ImageFormat::Jpeg))
        } else {
            Err(anyhow!(
                "error running ffmpeg: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    } else {
        Ok((
            content(&mut AsyncFile::open(full_path).await?).await?,
            ImageFormat::Jpeg,
        ))
    }
}

/// Parse the specified MPEG-4 file and extract its metadata.
async fn video_track_data(path: &Path, offset: i64) -> Result<VideoTrackData> {
    get_video_data(task::block_in_place(|| {
        let mut file = File::open(path)?;

        file.seek(SeekFrom::Start(offset.try_into().unwrap()))?;

        mp4parse::read_mp4(&mut file).map_err(Error::from)
    })?)
    .track_data
    .ok_or_else(|| {
        anyhow!(
            "unable to get video track data for {}",
            path.to_string_lossy()
        )
    })
}

/// Calculate an approximation of the average absolute difference between the bytes of the specified arrays.
fn average_absolute_difference(a: &[u8], b: &[u8]) -> usize {
    // For speed, look at only every Nth sample
    let step = 17;

    let (sum, count) = a
        .iter()
        .step_by(step)
        .zip(b.iter().step_by(step))
        .fold((0, 0), |(sum, count), (&a, &b)| {
            ((sum + ((a as i32) - (b as i32)).abs() as usize), count + 1)
        });

    sum / count
}

/// Produce a quality rating for the specified image, useful for comparing two duplicates and choosing the "best" one.
async fn quality(image_dir: &str, path: &str) -> Result<u64> {
    // Currently, we compute the quality as width*height.
    //
    // TODO: Investigate whether files contain metadata about encoding parameters and/or how many "generations" a
    // file is away from the original.

    let full_path = [image_dir, path].iter().collect::<PathBuf>();

    let lowercase = path.to_lowercase();

    let (width, height) = if lowercase.ends_with(".mp4") || lowercase.ends_with(".mov") {
        video_track_data(&full_path, 0).await?.dimensions
    } else {
        // TODO: Can we easily get the dimensions without completely decoding the image?  Using `rexiv2`, perhaps?
        image::load_from_memory_with_format(
            &content(&mut AsyncFile::open(full_path).await?).await?,
            ImageFormat::Jpeg,
        )?
        .dimensions()
    };

    Ok(width as u64 * height as u64)
}

/// Group `potential_duplicates` according to which ones appear to be duplicates of each other.
///
/// Each group in the result will be sorted from highest quality to lowest quality.
pub async fn deduplicate<'a>(
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    cache_dir: &str,
    potential_duplicates: &'a [ItemData],
) -> Result<Vec<Vec<&'a ItemData>>> {
    if potential_duplicates.len() == 1 {
        return Ok(vec![potential_duplicates.iter().collect()]);
    }

    let mut images = stream::iter(potential_duplicates)
        .then(|item| async move {
            Ok::<_, Error>((
                item,
                quality(image_dir, &item.file.path).await?,
                Vec::from(
                    &webp::Decoder::new(
                        &content(
                            &mut thumbnail(
                                Some(image_lock),
                                image_dir,
                                &item.file.path,
                                cache_dir,
                                Size::Small,
                                &item.hash,
                            )
                            .await?
                            .0,
                        )
                        .await?,
                    )
                    .decode()
                    .ok_or_else(|| anyhow!("unable to decode {}", &item.file.path))?
                        as &[u8],
                ),
            ))
        })
        .try_collect::<VecDeque<_>>()
        .await?;

    let mut duplicates = Vec::new();
    let mut group = Vec::new();

    loop {
        if let Some((item, quality, image)) = images.pop_front() {
            group.push((item, quality));

            let mut new_images = VecDeque::new();

            loop {
                if let Some((my_item, my_quality, my_image)) = images.pop_front() {
                    // We calculate the average absolute difference between each channel value of each pixel to
                    // determine whether the images are duplicates.  This is crude compared to more sophisticated
                    // algorithms such as https://ece.uwaterloo.ca/~z70wang/research/ssim/.
                    //
                    // TODO: Use https://crates.io/crates/dssim-core instead of AAD here, but note that dssim-core
                    // is licensed under the AGPL, which may be an issue for some, so it should probably only be
                    // enabled as an optional feature.

                    if average_absolute_difference(&image, &my_image)
                        <= MAX_AVERAGE_ABSOLUTE_DIFFERENCE
                    {
                        group.push((my_item, my_quality));
                    } else {
                        new_images.push_front((my_item, my_quality, my_image));
                    }
                } else {
                    group.sort_by(|(_, a), (_, b)| b.cmp(a));
                    duplicates.push(group.iter().map(|(a, _)| *a).collect::<Vec<_>>());
                    group = Vec::new();
                    images = new_images;
                    break;
                }
            }
        } else {
            break Ok(duplicates);
        }
    }
}

/// Calculate the perceptual hash of the media item at the specified `path`.
pub async fn perceptual_hash(
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    cache_dir: &str,
    hash: &str,
    path: &str,
    video_offset: Option<i64>,
) -> Result<String> {
    const HASH_WIDTH: u32 = 8;
    const HASH_HEIGHT: u32 = 8;

    let perceptual_hash = webp::Decoder::new(
        &content(
            &mut thumbnail(
                Some(image_lock),
                image_dir,
                path,
                cache_dir,
                Size::Small,
                hash,
            )
            .await?
            .0,
        )
        .await?,
    )
    .decode()
    .ok_or_else(|| anyhow!("unable to decode {}", path))?
    .to_image()
    .resize_exact(HASH_WIDTH, HASH_HEIGHT, FilterType::Lanczos3)
    .pixels()
    .map(|(_, _, Rgba(color))| {
        format!(
            "{:02x}",
            (color[0] & 0b1110_0000) | ((color[1] & 0b1110_0000) >> 3) | (color[2] >> 6)
        )
    })
    .collect::<Vec<_>>()
    .concat();

    Ok(if video_offset == Some(0) {
        format!(
            "{}-{}",
            perceptual_hash,
            video_track_data(&[image_dir, path].iter().collect::<PathBuf>(), 0)
                .await?
                .duration
                .as_secs()
        )
    } else {
        perceptual_hash
    })
}

/// Generate any missing thumbnail and preview artifacts for each of the specified items.
///
/// If an error is produced while generating artifacts for a given item, that error will be logged and this
/// function will continue on to the next item.
///
/// See also [preload_cache].
pub async fn preload_cache_all(
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    cache_dir: &str,
    mut images: impl Stream<Item = Result<ItemData, sqlx::Error>> + Unpin,
) -> Result<()> {
    while let Some(item) = images.try_next().await? {
        if let Err(e) =
            preload_cache(image_lock, image_dir, &item.file, cache_dir, &item.hash).await
        {
            tracing::warn!("error preloading cache for {}: {:?}", item.hash, e);
        }
    }

    Ok(())
}

/// Generate any missing thumbnail and preview artifacts for each of the specified item.
pub async fn preload_cache(
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    file_data: &FileData,
    cache_dir: &str,
    hash: &str,
) -> Result<()> {
    for size in &[Size::Small, Size::Large] {
        get_variant(
            image_lock,
            image_dir,
            file_data,
            cache_dir,
            Variant::Still(*size),
            hash,
        )
        .await?;

        if file_data.video_offset.is_some() {
            get_variant(
                image_lock,
                image_dir,
                file_data,
                cache_dir,
                Variant::Video(*size),
                hash,
            )
            .await?;
        }
    }

    Ok(())
}

/// Return a handle to the file containing the requested artifact, which will be generated on the fly from the
/// original media item if it doesn't already exist.
///
/// The return value is a tuple containing the file handle, MIME type, and length.
async fn get_variant(
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    file_data: &FileData,
    cache_dir: &str,
    variant: Variant,
    hash: &str,
) -> Result<(AsyncFile, &'static str, u64)> {
    match variant {
        Variant::Still(size) => {
            let (thumbnail, length, _) = thumbnail(
                Some(image_lock),
                image_dir,
                &file_data.path,
                cache_dir,
                size,
                hash,
            )
            .await?;

            Ok((thumbnail, "image/webp", length))
        }

        Variant::Video(size) => {
            if let Some(offset) = file_data.video_offset {
                let (preview, length) = video_preview(
                    image_lock,
                    image_dir,
                    &file_data.path,
                    offset,
                    cache_dir,
                    size,
                    hash,
                )
                .await?;

                Ok((preview, "video/mp4", length))
            } else {
                Err(HttpError::from_slice(StatusCode::NOT_FOUND, "not found").into())
            }
        }

        Variant::Original => {
            let lowercase = file_data.path.to_lowercase();

            let file =
                AsyncFile::open([image_dir, &file_data.path].iter().collect::<PathBuf>()).await?;
            let length = file.metadata().await?.len();

            Ok((
                file,
                if lowercase.ends_with(".mp4") || lowercase.ends_with(".mov") {
                    "video/mp4"
                } else {
                    "image/jpeg"
                },
                length,
            ))
        }
    }
}

/// Collect the contents of the specified file into a `Vec<u8>` and return it.
async fn content(file: &mut AsyncFile) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).await?;

    Ok(buffer)
}

/// Calculate the FFmpeg "-vf" parameter appropriate for scaling the specified video to the specified resolution.
async fn video_scale(
    image_dir: &str,
    path: &str,
    cache_dir: &str,
    size: Size,
    hash: &str,
) -> Result<String> {
    let image = webp::Decoder::new(
        &content(
            &mut thumbnail(None, image_dir, path, cache_dir, size, hash)
                .await?
                .0,
        )
        .await?,
    )
    .decode()
    .ok_or_else(|| anyhow!("invalid WebP image"))?;

    let mut width = image.width();
    let mut height = image.height();

    // The H.264 encoder requires both dimensions to be divisible by 2.

    if width % 2 != 0 {
        width -= 1;
    }

    if height % 2 != 0 {
        height -= 1;
    }

    Ok(format!("scale={}:{},setsar=1:1", width, height))
}

/// Return true iff the specified `entry` has an audio codec supported by all modern web browsers.
fn audio_supported(entry: &SampleEntry) -> bool {
    static SUPPORTED_AUDIO_CODECS: &[CodecType] = &[CodecType::AAC, CodecType::MP3];

    if let SampleEntry::Audio(entry) = entry {
        SUPPORTED_AUDIO_CODECS
            .iter()
            .any(|&codec| codec == entry.codec_type)
    } else {
        false
    }
}

/// Represents metadata for the primary track of an MPEG-4 video
struct VideoTrackData {
    /// The width and height of the primary video track
    dimensions: (u32, u32),

    /// The duration of the primary video track
    duration: Duration,

    /// The ID of the primary video track
    id: usize,
}

/// Represents metadata for an MPEG-4 video
struct VideoData {
    /// True iff the file contains only audio tracks which are not known to be supported by all modern web
    /// browsers
    need_audio_transcode: bool,

    /// See `VideoTrackData`
    ///
    /// If this is `None`, then no video track was found in the file.
    track_data: Option<VideoTrackData>,
}

/// Extract relevant metadata from the specified `context`.
///
/// This function tries to identify at least one audio track which is encoded with a codec supported by all modern
/// web browsers, as well as which video track, if any, is the longest, which we consider to be the "primary" video
/// track.
fn get_video_data(context: MediaContext) -> VideoData {
    let mut audio = None;
    let mut video = None;

    for track in context.tracks {
        match track.track_type {
            TrackType::Audio => {
                audio = audio
                    .and_then(|audio: Track| {
                        if let Some(audio_descriptions) = &audio.stsd {
                            if audio_descriptions.descriptions.iter().any(audio_supported)
                                || track.stsd.is_none()
                            {
                                Some(audio)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .or(Some(track))
            }

            TrackType::Video => {
                video = video
                    .and_then(|video: Track| {
                        if let Some(video_duration) = &video.duration {
                            if let Some(track_duration) = &track.duration {
                                if video_duration.0 >= track_duration.0 {
                                    Some(video)
                                } else {
                                    None
                                }
                            } else {
                                Some(video)
                            }
                        } else {
                            None
                        }
                    })
                    .or(Some(track))
            }

            _ => (),
        }
    }

    VideoData {
        need_audio_transcode: if let Some(audio) = audio {
            if let Some(audio_descriptions) = &audio.stsd {
                !audio_descriptions.descriptions.iter().any(audio_supported)
            } else {
                false
            }
        } else {
            false
        },

        track_data: video.map(|video| VideoTrackData {
            dimensions: video
                .tkhd
                .map(|tkhd| (tkhd.width, tkhd.height))
                .unwrap_or((0, 0)),

            duration: Duration::from_nanos(
                video
                    .duration
                    .zip(video.timescale)
                    .and_then(|(duration, timescale)| {
                        duration.0.checked_mul(1_000_000_000 / timescale.0)
                    })
                    .unwrap_or(0),
            ),

            id: video.id,
        }),
    }
}

/// Async-friendly wrapper for `NamedTempFile`
///
/// See `TempFile::drop` for why this wrapper exists.
pub struct TempFile(pub Option<NamedTempFile>);

impl Drop for TempFile {
    /// Drop the inner `NamedTempFile` inside a `task::block_in_place` context so that Tokio knows this thread may
    /// block on synchronous I/O.
    fn drop(&mut self) {
        task::block_in_place(|| drop(self.0.take()))
    }
}

/// Create a temporary file containing the suffix of the file at `path` starting at `offset` bytes from the
/// beginning.
async fn copy_from_offset(path: &Path, offset: i64) -> Result<TempFile> {
    let mut original = AsyncFile::open(path).await?;

    original
        .seek(SeekFrom::Start(offset.try_into().unwrap()))
        .await?;

    let mut tmp = TempFile(Some(task::block_in_place(NamedTempFile::new)?));

    let mut buffer = vec![0; crate::BUFFER_SIZE];

    loop {
        let count = original.read(&mut buffer[..]).await?;
        if count == 0 {
            break;
        } else {
            task::block_in_place(|| tmp.0.as_mut().unwrap().write_all(&buffer[0..count]))?;
        }
    }

    Ok(tmp)
}

/// Generate a preview version of the specified video at the requested resolution.
///
/// If `size` is `Size::Small`, the clip will be truncated to [VIDEO_PREVIEW_LENGTH_HMS] and resampled to
/// [SMALL_BOUNDS].  If `size` is `Size::Large` will be resampled to [LARGE_BOUNDS] and not truncated.
///
/// The return value is a tuple containing the file handle and length.
async fn video_preview(
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    path: &str,
    offset: i64,
    cache_dir: &str,
    size: Size,
    hash: &str,
) -> Result<(AsyncFile, u64)> {
    let filename = format!("{}/video/{}/{}.mp4", cache_dir, size, hash);

    let read = image_lock.read().await;

    let result = AsyncFile::open(&filename).await;

    if let Ok(file) = result {
        let length = file.metadata().await?.len();

        Ok((file, length))
    } else {
        drop(read);

        let _write = image_lock.write().await;

        if let Some(parent) = Path::new(&filename).parent() {
            if let Some(parent) = parent.parent() {
                let _ = fs::create_dir(parent).await;
            }
            let _ = fs::create_dir(parent).await;
        }

        let full_path = [image_dir, path].iter().collect::<PathBuf>();

        let video_data = get_video_data(task::block_in_place(|| {
            let mut file = File::open(&full_path)?;

            file.seek(SeekFrom::Start(offset.try_into().unwrap()))?;

            mp4parse::read_mp4(&mut file).map_err(Error::from)
        })?);

        let output = match size {
            Size::Small => {
                let scale = video_scale(image_dir, path, cache_dir, Size::Small, hash).await?;

                if offset == 0 {
                    Command::new("ffmpeg")
                        .arg("-i")
                        .arg(&full_path)
                        .arg("-ss")
                        .arg("00:00:00")
                        .arg("-to")
                        .arg(VIDEO_PREVIEW_LENGTH_HMS)
                        .arg("-vf")
                        .arg(&scale)
                        .arg("-an")
                        .arg(&filename)
                        .output()
                        .await
                } else {
                    let tmp = copy_from_offset(&full_path, offset).await?;

                    let mut command = Command::new("ffmpeg");

                    command.arg("-i").arg(tmp.0.as_ref().unwrap().path());

                    if let Some(track_data) = video_data.track_data {
                        command.arg("-map").arg(format!("0:{}", track_data.id));
                    }

                    command
                        .arg("-vf")
                        .arg(&scale)
                        .arg("-an")
                        .arg(&filename)
                        .output()
                        .await
                }
            }

            Size::Large => {
                if offset == 0 {
                    // Transcode video to reduce file size.
                    //
                    // TODO: We should first check whether the original file is already a reasonable size
                    // (i.e. given its dimensions and duration), in which case we can skip this step and just serve
                    // up the original file.
                    Command::new("ffmpeg")
                        .arg("-i")
                        .arg(&full_path)
                        .arg("-vcodec")
                        .arg("libx264")
                        .arg("-crf")
                        .arg("24") // see https://trac.ffmpeg.org/wiki/Encode/H.264#crf
                        .arg("-acodec")
                        .arg(if video_data.need_audio_transcode {
                            "mp3"
                        } else {
                            "copy"
                        })
                        .arg(&filename)
                        .output()
                        .await
                } else if let Some(track_data) = video_data.track_data {
                    let tmp = copy_from_offset(&full_path, offset).await?;

                    Command::new("ffmpeg")
                        .arg("-i")
                        .arg(tmp.0.as_ref().unwrap().path())
                        .arg("-map")
                        .arg(format!("0:{}", track_data.id))
                        .arg("-vcodec")
                        .arg("copy")
                        .arg("-an")
                        .arg(&filename)
                        .output()
                        .await
                } else {
                    let mut file = AsyncFile::open(&full_path).await?;
                    let offset = offset.try_into().unwrap();
                    let length = file.metadata().await?.len() - offset;

                    file.seek(SeekFrom::Start(offset)).await?;

                    return Ok((file, length));
                }
            }
        }?;

        if output.status.success() {
            let file = AsyncFile::open(&filename).await?;
            let length = file.metadata().await?.len();

            Ok((file, length))
        } else {
            let _ = fs::remove_file(&filename).await;

            Err(anyhow!(
                "error running ffmpeg: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

/// Find the still image preview for the specified media item and specified size, generating it from the original
/// if it doesn't already exist.
///
/// The return value is a tuple containing the file handle, length, and filename.
async fn thumbnail(
    image_lock: Option<&AsyncRwLock<()>>,
    image_dir: &str,
    path: &str,
    cache_dir: &str,
    size: Size,
    hash: &str,
) -> Result<(AsyncFile, u64, PathBuf)> {
    let filename = format!("{}/{}/{}.webp", cache_dir, size, hash);

    let read = if let Some(image_lock) = image_lock {
        Some(image_lock.read().await)
    } else {
        None
    };

    let result = AsyncFile::open(&filename).await;

    Ok(if let Ok(file) = result {
        let length = file.metadata().await?.len();

        (file, length, filename.into())
    } else {
        drop(read);

        let _write = if let Some(image_lock) = image_lock {
            Some(image_lock.write().await)
        } else {
            None
        };

        let (image, format) = still_image(image_dir, path).await?;

        let original = image::load_from_memory_with_format(&image, format)?;

        if let Some(parent) = Path::new(&filename).parent() {
            let _ = fs::create_dir(parent).await;
        }

        {
            let orientation = ExifMetadata::new_from_buffer(&image)
                .map(|metadata| {
                    let orientation = metadata.get_orientation();
                    metadata.clear();
                    metadata.set_orientation(orientation);
                    metadata
                })
                .as_ref()
                .map(|m| m.get_orientation())
                .unwrap_or(Orientation::Normal);

            let (width, height) = bound(
                original.dimensions(),
                match size {
                    Size::Small => SMALL_BOUNDS,
                    Size::Large => LARGE_BOUNDS,
                },
                orientation,
            );

            task::block_in_place(|| {
                let transformed = original.resize(width, height, FilterType::Lanczos3);

                let transformed = match orientation {
                    Orientation::Rotate90 => transformed.rotate90(),
                    Orientation::Rotate180 => transformed.rotate180(),
                    Orientation::Rotate270 => transformed.rotate270(),
                    Orientation::Normal | Orientation::Unspecified => transformed,
                    _ => return Err(anyhow!("unsupported orientation: {:?}", orientation)),
                };

                File::create(&filename)?.write_all(
                    &webp::Encoder::from_image(&transformed)
                        .map_err(|e| anyhow!("{}", e))?
                        .encode(WEBP_QUALITY),
                )?;

                Ok::<_, Error>(())
            })?;
        }

        let file = AsyncFile::open(&filename).await?;
        let length = file.metadata().await?.len();

        (file, length, filename.into())
    })
}

/// Convert the specified `AsyncRead` into a `Stream` of `Bytes`.
///
/// The latter is what Warp needs when sending a binary response which we don't want to load into memory all at
/// once.
fn as_stream(input: impl AsyncRead + Send) -> impl Stream<Item = Result<Bytes>> + Send {
    FramedRead::new(input, BytesCodec::new())
        .map_ok(BytesMut::freeze)
        .map_err(Error::from)
}

/// Handle a GET /image/.. request.
///
/// `hash` specifies which image is requested, while `variant` specifies which version of the image is requested.
///
/// `if_modified_since` and `ranges` enable cache control and HTTP range requests, respectively.  All responses are
/// considered immutable, so if `if_modified_since` is non-empty, we'll send a 304 Not Modified with no further
/// consideration.
#[allow(clippy::too_many_arguments)]
pub async fn image(
    conn: &AsyncMutex<SqliteConnection>,
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    cache_dir: &str,
    hash: &str,
    variant: Variant,
    if_modified_since: Option<HttpDate>,
    ranges: Option<&Ranges>,
) -> Result<Response<Body>> {
    if if_modified_since.is_some() {
        return Ok(crate::response()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())?);
    }

    let file_data = file_data(conn.lock().await.deref_mut(), hash).await?;

    let (mut image, content_type, length) =
        get_variant(image_lock, image_dir, &file_data, cache_dir, variant, hash).await?;

    let cache_control = "public, max-age=31536000, immutable";

    Ok(if let Some(Ranges(ranges)) = ranges {
        if ranges.len() == 1 {
            let range = &ranges[0];

            let (start, end) = match (range.start, range.end) {
                (Some(start), Some(end)) => (start, end + 1),
                (Some(start), None) => (start, length),
                (None, Some(end)) => (length - end, length),
                _ => (0, length),
            };

            if start > length
                || end > length
                || start > end
                || i64::try_from(start).is_err()
                || end == 0
            {
                return Err(HttpError::from_slice(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "range not satisfiable",
                )
                .into());
            }

            image
                .seek(SeekFrom::Current(start.try_into().unwrap()))
                .await?;

            crate::response()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end - 1, length),
                )
                .header(header::CONTENT_LENGTH, end - start)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CACHE_CONTROL, cache_control)
                .body(Body::wrap_stream(as_stream(image.take(end - start))))?
        } else {
            // This wouldn't be hard to support, but I don't know if and when any modern web browser makes
            // multi-range requests; no need to implement something if it will never be used.
            return Err(HttpError::from_slice(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "multiple ranges not yet supported",
            )
            .into());
        }
    } else {
        crate::response()
            .header(header::CONTENT_LENGTH, length)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CACHE_CONTROL, cache_control)
            .body(Body::wrap_stream(as_stream(image)))?
    })
}
