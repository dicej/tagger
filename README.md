# Tagger

A simple photo and video organizer for the web

## Summary

This is web app for organizing and browsing photo and video collections.  Media
are organized by date by default, and users may add custom tags for querying and
access control.

This app doesn't (currently) support uploading images.  Instead, it watches a
directory waiting for new media items to appear.  This is intended to work in
tandem with e.g. [Syncthing](https://syncthing.net/) such that images from your
phone and/or other devices are continuously synced to the server running the
`Tagger` back end.  Media items will appear in your collection automatically as
they are added to the filesystem.

## Features

* Supports JPEG images (including "motion photo" files with embedded videos
  created by some Android phones) and MPEG-4 videos
* Periodically syncs with filesystem to find new media items
* Generates and caches thumbnail and preview clips
* Automatically organizes by creation date
* Supports adding and filtering by custom tags and categories
 * UI supports bulk tag/untag operations on many items at once
* Supports multiple user accounts, each with access control based on tags
* Automatically transcodes to web-standard codecs
* Deduplicates identical files
* Supports HTTP Range headers for efficient video buffering in modern browsers
* Mobile-friendly

## Not yet supported (but maybe someday)

* Inexact deduplication (e.g. resampled duplicates)
* Automatic location tagging based on embedded GPS coordinates
* Automatic tagging based on face recognition
* Uploading images within the app (use e.g. [Syncthing](https://syncthing.net/)
  instead)
* User account management within the app (use the `tagger_admin` tool and/or
  SQLite CLI instead)
* Simple image and video editing (e.g. crop, rotate, trim)

## Supported platform(s)

The back end server has been tested on Ubuntu 20.04 LTS.  It will probably work
with minimal or no changes on other platforms, but I haven't tried that yet.

The front end is a WebAssembly-based single page app and has been tested with
recent Firefox, Chrome, and Safari browsers on various desktop and mobile
devices.

## Security

### TLS

The server supports TLS (via the `--cert-file` and `--key-file` CLI options),
which is strongly recommended.  Most modern browsers have a growing list of
restrictions for plaintext HTTP sites, so Tagger may not even work correctly in
your browser without TLS.  Fortunately, services like [Let's
Encrypt](https://letsencrypt.org/) make this easy.

### Media item URLs

Each user account may include a tag query which limits the media items
discoverable by that user to those which satisfy the query.

*However*, media items URLs themselves are not subject to access control.  This
makes it possible to share media item URLs without sharing session tokens, but
it also means there's no way to restrict access to a given item after someone
has the URL except by removing it from the server entirely.

Media item URLs include the SHA-256 of their content, so discovering them by
brute force without prior knowledge is infeasible, but once a user has the URL
they have unlimited access and can share it with anyone.

## Building, installing and running

First, install [FFmpeg](https://ffmpeg.org/) if you want video support, e.g.

```bash
sudo apt install ffmpeg
```

Next, install the latest [Rust toolchain](https://rustup.rs/) if you don't
already have a recent one:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then install [Trunk](https://trunkrs.dev/):

```bash
cargo install --locked trunk
```

Then install [Binaryen](https://github.com/webassembly/binaryen):

```bash
sudo apt install binaryen
```

Then build the client and server code:

```bash
(cd client && trunk build --release)
cargo build --release
```

Create some directories for the server to store its state in, and create an
account using the `tagger_admin` tool:

```bash
mkdir -p ~/tagger/cache
./target/release/tagger_admin add-user ~/tagger/database.dat my_user my_password --may-patch
```

Finally, run the server, e.g.

```bash
RUST_LOG=tagger=info,tagger_server=info ./target/release/tagger_server \
  --address 127.0.0.1:8080 \
  --image-directory ~/directory_containing_my_image_collection \
  --public-directory client/dist/ \
  --state-file ~/tagger/database.dat \
  --cache-directory ~/tagger/cache \
  --preload-cache
```

Then open http://localhost.com:8080 in your browser and log in using the
credentials you specified above.  You should (eventually) see the photos and
videos in your collection, although it may take a while for everything to to be
added to the database if your collection is large.

For CLI documentation, run:

```bash
target/release/tagger_server --help
```

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
</sub>
