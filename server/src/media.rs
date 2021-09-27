use {
    crate::warp_util::{HttpDate, HttpError, Ranges},
    anyhow::{anyhow, Error, Result},
    bytes::{Bytes, BytesMut},
    futures::{Stream, TryStreamExt},
    http::{header, status::StatusCode, Response},
    hyper::Body,
    image::{imageops::FilterType, GenericImageView, ImageFormat},
    mp4parse::{CodecType, MediaContext, SampleEntry, Track, TrackType},
    rexiv2::{Metadata as ExifMetadata, Orientation},
    sqlx::SqliteConnection,
    std::{
        convert::{TryFrom, TryInto},
        fs::File,
        io::{Seek, SeekFrom, Write},
        mem,
        ops::DerefMut,
        path::{Path, PathBuf},
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

pub const SMALL_BOUNDS: (u32, u32) = (480, 320);

pub const LARGE_BOUNDS: (u32, u32) = (1920, 1280);

const WEBP_QUALITY: f32 = 85.0;

const VIDEO_PREVIEW_LENGTH_HMS: &str = "00:00:05";

pub struct FileData {
    pub path: String,
    pub video_offset: Option<i64>,
}

#[allow(clippy::eval_order_dependence)]
async fn file_data(conn: &mut SqliteConnection, path: &str) -> Result<FileData> {
    if let (Some(path), Some(image)) = (
        sqlx::query!("SELECT path FROM paths WHERE hash = ?1 LIMIT 1", path)
            .fetch_optional(&mut *conn)
            .await?,
        sqlx::query!(
            "SELECT video_offset FROM images WHERE hash = ?1 LIMIT 1",
            path
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

fn orthagonal(orientation: Orientation) -> bool {
    matches!(
        orientation,
        Orientation::Rotate90HorizontalFlip
            | Orientation::Rotate90
            | Orientation::Rotate90VerticalFlip
            | Orientation::Rotate270
    )
}

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
        let mut file = AsyncFile::open(full_path).await?;

        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer).await?;

        Ok((buffer, ImageFormat::Jpeg))
    }
}

pub async fn preload_cache_all(
    image_lock: &AsyncRwLock<()>,
    image_dir: &str,
    cache_dir: &str,
    mut images: impl Stream<Item = Result<(String, FileData), sqlx::Error>> + Unpin,
) -> Result<()> {
    while let Some((hash, file_data)) = images.try_next().await? {
        if let Err(e) = preload_cache(image_lock, image_dir, &file_data, cache_dir, &hash).await {
            tracing::warn!("error preloading cache for {}: {:?}", hash, e);
        }
    }

    Ok(())
}

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

async fn content(file: &mut AsyncFile) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).await?;

    Ok(buffer)
}

async fn video_scale(
    image_dir: &str,
    path: &str,
    cache_dir: &str,
    size: Size,
    hash: &str,
) -> Result<String> {
    let mut thumbnail = thumbnail(None, image_dir, path, cache_dir, size, hash)
        .await?
        .0;

    let (mut width, mut height) = webp::Decoder::new(&content(&mut thumbnail).await?)
        .decode()
        .map(|image| image.to_image())
        .ok_or_else(|| anyhow!("invalid WebP image"))?
        .dimensions();

    if width % 2 != 0 {
        width -= 1;
    }

    if height % 2 != 0 {
        height -= 1;
    }

    Ok(format!("scale={}:{},setsar=1:1", width, height))
}

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

struct VideoData {
    need_audio_transcode: bool,
    pick_video_stream: Option<usize>,
}

fn get_video_data(context: MediaContext) -> VideoData {
    let mut audio = None;
    let mut video = None;
    let mut video_track_count = 0;

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
                video_track_count += 1;

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

        pick_video_stream: if video_track_count > 1 {
            video.map(|video| video.id)
        } else {
            None
        },
    }
}

pub struct TempFile(pub Option<NamedTempFile>);

impl Drop for TempFile {
    fn drop(&mut self) {
        task::block_in_place(|| drop(self.0.take()))
    }
}

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

                    if let Some(id) = video_data.pick_video_stream {
                        command.arg("-map").arg(format!("0:{}", id));
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
                } else if let Some(id) = video_data.pick_video_stream {
                    let tmp = copy_from_offset(&full_path, offset).await?;

                    Command::new("ffmpeg")
                        .arg("-i")
                        .arg(tmp.0.as_ref().unwrap().path())
                        .arg("-map")
                        .arg(format!("0:{}", id))
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

fn as_stream(input: impl AsyncRead + Send) -> impl Stream<Item = Result<Bytes>> + Send {
    FramedRead::new(input, BytesCodec::new())
        .map_ok(BytesMut::freeze)
        .map_err(Error::from)
}

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
        { get_variant(image_lock, image_dir, &file_data, cache_dir, variant, hash).await }?;

    let cache_control = "public, max-age=31536000, immutable";

    Ok(if let Some(ranges) = ranges {
        if ranges.0.len() == 1 {
            let range = &ranges.0[0];

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
