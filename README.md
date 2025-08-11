# PixelPress Image Compressor

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-Custom-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

A fast, modern desktop app to compress and batch-convert images with a polished Tkinter UI. It supports drag-and-drop, robust URL ingestion, a live thumbnail gallery, persistent preferences (output folder and theme), and JPEG/PNG/WEBP export.

## Features

* Drag-and-drop files, folders, and URLs directly into the queue.
* Robust URL fetching with retries and redirect support.
* Live Gallery panel: previews thumbnails for all queued items.
* Output formats: auto, JPEG, PNG, WEBP; configurable quality and optional resize.
* Persistent settings for last-used output folder and theme.
* Light/Dark themes with ttkbootstrap.
* Status log and progress bar with per-item success/error notes.

## Screenshots
* docs/light_mode.png — main UI in light theme
* docs/dark_mode.png — main UI in dark theme
* docs/progress.png — compression in progress

## Installation

### For Users

1. Download the latest `mysetup.exe` from the Releases section.
2. Run the installer and follow the on-screen instructions.
3. Launch **PixelPress Image Compressor** from the Start Menu or Desktop shortcut.

### For Developers

1. Clone the repository:

   ```bash
   git clone https://github.com/Sayangithub23/pixelpress-image-compressor.git
   cd pixelpress-image-compressor
   ```
2. Create and activate a virtual environment:

   * Windows (PowerShell):

     ```powershell
     py -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   * macOS/Linux:

     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
4. Run the app:

   ```bash
   python main.py
   ```

## Usage

* Add files, folders, or URLs to the queue.
* Set output format, quality, and optional resize dimensions.
* Click **Compress** to start.
* Find the compressed images in your chosen output folder.

## License

```
PixelPress Image Compressor
Copyright (c) 2025 Sayan Dey

All rights reserved.

Permission is granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to use
and distribute the Software in binary form for personal or commercial purposes,
subject to the following conditions:

1. The Software must not be modified, reverse-engineered, or redistributed
   in altered form without prior written permission from the copyright holder.

2. Proper credit must be given in any use, distribution, or publication
   of the Software. This includes retaining this copyright notice
   in all copies of the Software.

3. This Software is provided "AS IS", without warranty of any kind, express or
   implied, including but not limited to the warranties of merchantability,
   fitness for a particular purpose, and noninfringement. In no event shall
   the author is liable for any claim, damages, or other liability arising
   from the use of the Software.
```

## Credits

* ttkbootstrap for modern Tkinter themes.
* TkinterDnD2 for drag-and-drop support.

## Changelog

### v1.0.0 — Initial Release

* Added image compression for JPEG, PNG, and WEBP.
* Implemented drag-and-drop for files, folders, and URLs.
* Added persistent settings for theme and output folder.
* Included light/dark theme switching.
* Packaged with an installer for Windows.

