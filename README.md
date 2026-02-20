# dlnad: Simple DLNA Server for LG WebOS

A lightweight DLNA media server written in Rust, specifically optimized for LG WebOS TV clients.
Includes a simple GUI: a menu app for MacOS, useable to select a directory to share, to start and stop the service and to check the logs.

## Features

* **Dynamic Versioning**: Baked-in build timestamps for easy version tracking.
* **Dynamic Directory Browsing**: Scans the filesystem in real-time, allowing you to add videos or thumbnails without restarting the server.
* **Client Identification**: Logs the IP and resolved hostname (via Reverse DNS) of every new device that connects.
* **Metadata Extraction**: Reads embedded MP4 titles and durations using the `mp4ameta` crate.
* **Advanced Subtitle Support**:
  * Automatically detects `.srt` and `.vtt` files with matching filenames.
  * Implements `CaptionInfo.sec` and `srh` protocol headers required for LG/Samsung TVs.
* **Thumbnail Discovery**: Shows video previews by automatically linking `.jpg` or `.png` files.
* **Toggleable Caching**: Optional `--cache` flag to freeze directory listings in memory for faster performance.
* **Persistent Configuration**: Uses ~/.dlnad to store the choosen directory to share and the unique ID for the installation.

## Usage

```sh
dlnad [VERSION]
Gunther: A simple DLNA server for LG WebOS

Usage: dlnad [OPTIONS]

Options:
ptions:
  -p, --port <PORT>            [default: 8200]
  -i, --ip <IP_ADDRESS>        [default: 0.0.0.0]
  -d, --directory <DIRECTORY>  [default: .]
  -c, --cache
  -C, --config <CONFIG>        [env: DLNAD_CONFIG=]
  -n, --name <NAME>            [default: hostname]
  -v, --verbose
  -h, --help                   Print help
  -V, --version                Print version
```

## LG WebOS Compatibility Notes

To ensure subtitles and thumbnails appear correctly on LG TVs:

1. **Format**: External subtitles are most stable in `.srt` format (UTF-8 encoding without BOM).
2. **Naming**: Place your subtitle and image files in the same directory as the video with the exact same base name:

  * `Course_01.mp4`
  * `Course_01.srt`
  * `Course_01.jpg` (Thumbnail)

3. **Internal Logic**: This server uses the `pv:subtitleFileUri` attribute and `DLNA.ORG_PN=SUBTITLE` features to trigger the TV's native subtitle engine.

---

*Ramón Barrios Láscar, 2026*

---
