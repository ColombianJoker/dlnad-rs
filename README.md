---
# dlnad: Simple DLNA Server for LG WebOS

A lightweight DLNA media server written in Rust, specifically optimized for LG WebOS TV clients.

## Features

* **Dynamic Versioning**: Baked-in build timestamps for easy version tracking.
* **Metadata Extraction**: Reads embedded MP4 titles and durations using the `mp4ameta` crate.
* **Advanced Subtitle Support**:
* Automatically detects `.srt` and `.vtt` files with matching filenames.
* Implements `CaptionInfo.sec` and `srh` protocol headers required for LG/Samsung TVs.
* **Thumbnail Discovery**: Shows video previews by automatically linking `.jpg` or `.png` files.
* **Debug Mode**: Includes a full header trace to troubleshoot TV-to-Server handshakes.

## Usage

```sh
dlnad [VERSION]
Gunther: A simple DLNA server for LG WebOS

Usage: dlnad [OPTIONS]

Options:
  -p, --port <PORT>            [default: 8200]
  -i, --ip <IP_ADDRESS>        [default: 0.0.0.0]
  -d, --directory <DIRECTORY>  [default: .]
  -n, --name <NAME>            Friendly name for the DLNA server
  -v, --verbose                Enable info logging
  --debug                      Print full HTTP request/response headers
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
