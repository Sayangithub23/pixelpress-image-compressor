#!/usr/bin/env python3
"""
Pro Image Compressor - Enhanced and Fixed

Features:
- Robust progress and error handling
- Drag & drop (via TkinterDnD2)
- URL download with CDN and redirect support (multi-strategy Referer)
- Light/dark theme switching (ttkbootstrap)
- Output folder preference remembered across sessions
- Gallery panel previews all input images (local + URLs)
"""

import os
import io
import threading
import queue
import requests
import json
from pathlib import Path
from urllib.parse import urlparse
from PIL import Image, UnidentifiedImageError, ImageTk
import tkinter as tk
from tkinter import filedialog, messagebox, StringVar, IntVar, BooleanVar, END, NORMAL, DISABLED
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinterdnd2 import DND_FILES, TkinterDnD

# --------------- Configuration ----------------
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50MB
APP_DIR = Path(os.path.expanduser("~")) / ".pro_image_compressor"
APP_DIR.mkdir(exist_ok=True)
CONFIG_PATH = APP_DIR / "settings.json"
INVALID_CHARS = '<>:"/\\|?*'

def allowed_ext(name: str) -> bool:
    return os.path.splitext(name.lower())[1] in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}

def sanitize_filename(name: str, replacement: str = "_") -> str:
    # Remove invalid and control characters
    name = "".join(c if (c not in INVALID_CHARS and 31 < ord(c) < 127) else replacement for c in name)
    # Strip trailing spaces/dots (Windows)
    name = name.strip(" .")
    return name or "file"

def infer_format_from_name(name: str):
    ext = os.path.splitext(name.lower())[1]
    if ext in (".jpg", ".jpeg"):
        return "JPEG"
    if ext == ".png":
        return "PNG"
    if ext == ".webp":
        return "WEBP"
    return None

def load_image_from_bytes(data: bytes) -> Image.Image:
    im = Image.open(io.BytesIO(data))
    im.load()
    return im

def fetch_image_from_url(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Only valid HTTP/HTTPS URLs are allowed.")

    session = requests.Session()
    session.max_redirects = 5

    def make_headers(referer: str | None = None) -> dict:
        h = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "image/avif,image/webp,image/apng,image/*;q=0.8,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        if referer is not None:
            h["Referer"] = referer
        else:
            h["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"
        return h

    def download(headers: dict) -> bytes:
        with session.get(url, stream=True, timeout=30, headers=headers, allow_redirects=True) as r:
            if r.status_code != 200:
                raise ValueError(f"Could not fetch URL (status {r.status_code}).")
            try:
                content_len = int(r.headers.get("Content-Length", "0"))
                if content_len > 0 and content_len > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"Remote file too large (> {MAX_DOWNLOAD_BYTES // (1024*1024)} MB).")
            except Exception:
                pass
            data = bytearray()
            total = 0
            for chunk in r.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                data.extend(chunk)
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"Remote file too large (> {MAX_DOWNLOAD_BYTES // (1024*1024)} MB).")
        _ = load_image_from_bytes(bytes(data))  # validate
        return bytes(data)

    strategies = [
        make_headers(None),  # site root as referer
        make_headers(url),   # self-referer
    ]
    last_error = None
    for h in strategies:
        try:
            return download(h)
        except Exception as e:
            last_error = e
            continue
    # last try: no referer
    try:
        return download(make_headers(referer=""))
    except Exception:
        pass
    raise last_error or ValueError("Could not fetch URL (403 or blocked by host).")

def guess_save_name_from_url(url: str, out_fmt: str) -> str:
    path = urlparse(url).path
    base = os.path.basename(path)
    name, ext = os.path.splitext(base)
    if not name:
        name = "remote_image"
    name = sanitize_filename(name)
    if not ext or len(ext) > 6 or any(c in ext for c in ("?", "&", "=")):
        ext = CompressorWorker._ext_from_fmt(out_fmt, fallback=".png")
    return f"{name}_compressed{ext}"

def resize_to_fit(im: Image.Image, max_w: int, max_h: int) -> Image.Image:
    if max_w <= 0 and max_h <= 0:
        return im
    w, h = im.size
    scale_w = max_w / w if max_w > 0 else 1.0
    scale_h = max_h / h if max_h > 0 else 1.0
    scale = min(scale_w, scale_h)
    if scale >= 1.0:
        return im
    new_size = (max(1, int(w * scale)), max(1, int(h * scale)))
    return im.resize(new_size, Image.LANCZOS)

def normalize_mode_for_format(im: Image.Image, out_fmt: str) -> Image.Image:
    if out_fmt == "JPEG":
        if im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info):
            bg = Image.new("RGB", im.size, (255, 255, 255))
            alpha = im.split()[-1] if im.mode in ("RGBA", "LA") else None
            if alpha:
                bg.paste(im, mask=alpha)
            else:
                bg.paste(im)
            return bg
        if im.mode != "RGB":
            return im.convert("RGB")
        return im
    else:
        return im

def compress_image(input_bytes: bytes, src_name: str, out_fmt: str, quality: int,
                   max_w: int, max_h: int, save_path: str):
    im = load_image_from_bytes(input_bytes)
    fmt = out_fmt if out_fmt != "auto" else (infer_format_from_name(src_name) or (im.format or "PNG"))
    fmt = fmt.upper()
    im = resize_to_fit(im, max_w, max_h)
    im = normalize_mode_for_format(im, fmt)
    save_kwargs = {}
    if fmt in ("JPEG", "WEBP"):
        q = min(95, max(10, int(quality)))
        if fmt == "JPEG":
            save_kwargs.update({"quality": q, "optimize": True, "progressive": True})
        else:
            save_kwargs.update({"quality": q, "method": 6})
    elif fmt == "PNG":
        save_kwargs.update({"optimize": True})
    dirpath = os.path.dirname(save_path) or "."
    os.makedirs(dirpath, exist_ok=True)
    im.save(save_path, format=fmt, **save_kwargs)

def load_settings() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_settings(settings: dict):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass

# --------------- Worker Thread ----------------
class CompressorWorker(threading.Thread):
    def __init__(self, task_queue: queue.Queue, status_callback, done_callback, stop_flag: threading.Event):
        super().__init__(daemon=True)
        self.task_queue = task_queue
        self.status_callback = status_callback
        self.done_callback = done_callback
        self.stop_flag = stop_flag

    def run(self):
        try:
            while not self.task_queue.empty() and not self.stop_flag.is_set():
                item = self.task_queue.get()
                try:
                    self.process_item(item)
                except Exception as e:
                    self.status_callback(f"Error: {e}", error=True, saved=False)
                finally:
                    self.task_queue.task_done()
        finally:
            self.done_callback()

    def process_item(self, item):
        (file_path_or_url, is_url, out_dir, out_fmt, quality, max_w, max_h) = item
        if is_url:
            self.status_callback(f"Fetching URL: {file_path_or_url}", error=False, saved=False)
            data = fetch_image_from_url(file_path_or_url)
            save_name = guess_save_name_from_url(file_path_or_url, out_fmt)
            save_path = os.path.join(out_dir, save_name)
            compress_image(data, file_path_or_url, out_fmt, quality, max_w, max_h, save_path)
            self.status_callback(f"Saved: {save_name}", error=False, saved=True)
        else:
            if not os.path.isfile(file_path_or_url):
                raise FileNotFoundError(f"File not found: {file_path_or_url}")
            self.status_callback(f"Processing: {os.path.basename(file_path_or_url)}", error=False, saved=False)
            with open(file_path_or_url, "rb") as f:
                data = f.read()
            base = os.path.splitext(os.path.basename(file_path_or_url))[0]
            base = sanitize_filename(base)
            original_ext = os.path.splitext(file_path_or_url)[1] or ".png"
            save_name = f"{base}_compressed{self._ext_from_fmt(out_fmt, fallback=original_ext)}"
            save_path = os.path.join(out_dir, save_name)
            compress_image(data, file_path_or_url, out_fmt, quality, max_w, max_h, save_path)
            self.status_callback(f"Saved: {save_name}", error=False, saved=True)

    @staticmethod
    def _ext_from_fmt(out_fmt: str, fallback: str):
        if out_fmt == "JPEG":
            return ".jpg"
        if out_fmt == "PNG":
            return ".png"
        if out_fmt == "WEBP":
            return ".webp"
        return fallback

# --------------- Main Application ----------------
class ImageCompressorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PixelPress")
        self.style = tb.Style("cosmo")
        self.root.geometry("1080x700")
        self.root.minsize(840, 520)

        # state
        self.file_list = []
        self.task_queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.worker = None

        self.total_tasks = 0
        self.processed_count = 0
        self.log_entries = []

        # Persistent settings
        self.settings = load_settings()
        default_out = self.settings.get("output_dir", os.path.join(os.path.expanduser("~"), "Compressed_Images"))
        self.out_dir_var = StringVar(value=default_out)
        # Theme: default to saved theme or "cosmo"
        saved_theme = self.settings.get("theme", "cosmo")
        self.theme_var = StringVar(value=saved_theme)

        # Apply theme right away
        self.style = tb.Style(saved_theme)
        self.url_var = StringVar()
        self.format_var = StringVar(value="auto")
        self.quality_var = IntVar(value=80)
        self.resize_enable_var = BooleanVar(value=False)
        self.width_var = IntVar(value=0)
        self.height_var = IntVar(value=0)
        self.theme_var = StringVar(value="cosmo")

        # Gallery state
        self.thumb_size = (128, 128)
        self.thumb_images = []
        self.thumb_items = []
        self.thumb_queue = queue.Queue()

        self._build_ui()
        self._bind_dnd()
        self._log("Ready.")

    def _build_ui(self):
        top_bar = tb.Frame(self.root, padding=8)
        top_bar.pack(fill=X)
        tb.Label(top_bar, text="Pro Image Compressor", font=("Segoe UI", 16, "bold")).pack(side=LEFT)
        tb.Button(top_bar, text="Light", bootstyle=SECONDARY, command=lambda: self._set_theme("cosmo")).pack(side=RIGHT, padx=4)
        tb.Button(top_bar, text="Dark", bootstyle=SECONDARY, command=lambda: self._set_theme("darkly")).pack(side=RIGHT)

        main = tb.Panedwindow(self.root, orient=HORIZONTAL)
        main.pack(expand=YES, fill=BOTH, padx=10, pady=10)

        # Left panel: Input
        left = tb.Labelframe(main, text="Input", padding=10)
        main.add(left, weight=3)
        list_frame = tb.Frame(left)
        list_frame.pack(fill=BOTH, expand=YES)
        self.files_listbox = tk.Listbox(list_frame, selectmode=tk.EXTENDED, height=14)
        self.files_listbox.pack(side=LEFT, fill=BOTH, expand=YES)
        self.list_scrollbar = tb.Scrollbar(list_frame, orient="vertical", command=self.files_listbox.yview)
        self.list_scrollbar.pack(side=LEFT, fill=Y)
        self.files_listbox.config(yscrollcommand=self.list_scrollbar.set)

        btns_row = tb.Frame(left)
        btns_row.pack(fill=X, pady=(8, 6))
        tb.Button(btns_row, text="Add Files", bootstyle=PRIMARY, command=self.add_files).pack(side=LEFT)
        tb.Button(btns_row, text="Remove Selected", bootstyle=WARNING, command=self.remove_selected).pack(side=LEFT, padx=6)
        tb.Button(btns_row, text="Clear", bootstyle=DANGER, command=self.clear_files).pack(side=LEFT)

        # URL
        url_row = tb.Frame(left)
        url_row.pack(fill=X, pady=6)
        tb.Entry(url_row, textvariable=self.url_var).pack(side=LEFT, fill=X, expand=YES, padx=(0, 6))
        tb.Button(url_row, text="Add URL", bootstyle=INFO, command=self.add_url).pack(side=LEFT)
        tb.Label(left, text="Tip: Drag & drop files/folders/URLs here").pack(anchor=W, pady=(6, 0))

        # Right panel: Options
        right = tb.Labelframe(main, text="Options", padding=10)
        main.add(right, weight=2)

        out_row = tb.Frame(right)
        out_row.pack(fill=X, pady=4)
        tb.Label(out_row, text="Output Folder:").pack(side=LEFT, padx=(0, 8))
        tb.Entry(out_row, textvariable=self.out_dir_var).pack(side=LEFT, fill=X, expand=YES)
        tb.Button(out_row, text="Browse", bootstyle=SECONDARY, command=self.pick_output_dir).pack(side=LEFT, padx=6)

        fmt_row = tb.Frame(right)
        fmt_row.pack(fill=X, pady=4)
        tb.Label(fmt_row, text="Output Format:").pack(side=LEFT, padx=(0, 8))
        self.fmt_combo = tb.Combobox(fmt_row, values=["auto", "JPEG", "PNG", "WEBP"], textvariable=self.format_var, state="readonly", width=10)
        self.fmt_combo.pack(side=LEFT)

        q_row = tb.Frame(right)
        q_row.pack(fill=X, pady=4)
        tb.Label(q_row, text="Quality (10-95):").pack(side=LEFT, padx=(0, 8))
        self.q_spin = tb.Spinbox(q_row, from_=10, to=95, textvariable=self.quality_var, width=6)
        self.q_spin.pack(side=LEFT)

        resize_row = tb.Frame(right)
        resize_row.pack(fill=X, pady=6)
        tb.Checkbutton(resize_row, text="Resize", variable=self.resize_enable_var, command=self._toggle_resize).pack(side=LEFT)
        tb.Label(resize_row, text="Max W:").pack(side=LEFT, padx=(10, 4))
        self.w_spin = tb.Spinbox(resize_row, from_=0, to=20000, textvariable=self.width_var, width=8, state=DISABLED)
        self.w_spin.pack(side=LEFT)
        tb.Label(resize_row, text="Max H:").pack(side=LEFT, padx=(10, 4))
        self.h_spin = tb.Spinbox(resize_row, from_=0, to=20000, textvariable=self.height_var, width=8, state=DISABLED)
        self.h_spin.pack(side=LEFT)

        actions = tb.Frame(right)
        actions.pack(fill=X, pady=10)
        self.start_btn = tb.Button(actions, text="Compress", bootstyle=SUCCESS, command=self.start_compress)
        self.start_btn.pack(side=LEFT)
        self.cancel_btn = tb.Button(actions, text="Cancel", bootstyle=SECONDARY, command=self.cancel_compress, state=DISABLED)
        self.cancel_btn.pack(side=LEFT, padx=6)

        # Gallery panel
        gallery = tb.Labelframe(main, text="Gallery", padding=10)
        main.add(gallery, weight=3)
        self.gallery_canvas = tk.Canvas(gallery, highlightthickness=0)
        self.gallery_scroll = tb.Scrollbar(gallery, orient="vertical", command=self.gallery_canvas.yview)
        self.gallery_frame = tb.Frame(self.gallery_canvas)
        self.gallery_frame.bind(
            "<Configure>",
            lambda e: self.gallery_canvas.configure(scrollregion=self.gallery_canvas.bbox("all"))
        )
        self.gallery_canvas.create_window((0, 0), window=self.gallery_frame, anchor="nw")
        self.gallery_canvas.configure(yscrollcommand=self.gallery_scroll.set)
        self.gallery_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=tk.YES)
        self.gallery_scroll.pack(side=tk.LEFT, fill=tk.Y)

        # Status & progress
        status_box = tb.Labelframe(self.root, text="Status", padding=10)
        status_box.pack(fill=tk.BOTH, expand=tk.YES, padx=10, pady=(0, 10))
        self.progress = tb.Progressbar(status_box, bootstyle=INFO, maximum=100, value=0)
        self.progress.pack(fill=tk.X)
        self.status_text = tk.Text(status_box, height=10, wrap="word")
        self.status_text.pack(fill=tk.BOTH, expand=tk.YES, pady=(8, 0))

    def _bind_dnd(self):
        try:
            self.files_listbox.drop_target_register(DND_FILES)
            self.files_listbox.dnd_bind('<<Drop>>', self._on_drop)
        except Exception as e:
            self._log(f"Drag & drop not available: {e}", error=True)

    def _on_drop(self, event):
        try:
            paths = self.root.splitlist(event.data)
        except Exception:
            raw = event.data
            if raw.startswith("{") and raw.endswith("}"):
                raw = raw[1:-1]
            paths = raw.split()
        added = 0
        for p in paths:
            if os.path.isdir(p):
                for rootdir, _, files in os.walk(p):
                    for f in files:
                        full = os.path.join(rootdir, f)
                        if allowed_ext(full):
                            self._add_file(full)
                            self._build_thumb_from_file(full)
                            added += 1
            else:
                if allowed_ext(p):
                    self._add_file(p)
                    self._build_thumb_from_file(p)
                    added += 1
                else:
                    if p.lower().startswith(("http://", "https://")):
                        display = f"[URL] {p}"
                        if display not in self.file_list:
                            self.file_list.append(display)
                            self.files_listbox.insert(END, display)
                            self._build_thumb_from_url(p)
                            added += 1
        if added == 0:
            self._log("No supported images found in dropped items.", error=False)

    def _set_theme(self, theme_name: str):
        try:
            tb.Style(theme_name)
            self.settings["theme"] = theme_name  # save in settings
            save_settings(self.settings)         # write to disk
            self._log(f"Theme switched to: {theme_name}")
        except Exception as e:
            self._log(f"Failed to switch theme: {e}", error=True)

    def _toggle_resize(self):
        state = NORMAL if self.resize_enable_var.get() else DISABLED
        self.w_spin.configure(state=state)
        self.h_spin.configure(state=state)

    def _add_file(self, path):
        if path not in self.file_list:
            self.file_list.append(path)
            self.files_listbox.insert(END, path)

    def add_files(self):
        filenames = filedialog.askopenfilenames(
            title="Select Images",
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.webp;*.bmp;*.tiff")]
        )
        for f in filenames:
            self._add_file(f)
            self._build_thumb_from_file(f)

    def remove_selected(self):
        sel = list(self.files_listbox.curselection())
        sel.reverse()
        names_to_remove = []
        for idx in sel:
            path = self.files_listbox.get(idx)
            names_to_remove.append(path)
            try:
                self.file_list.remove(path)
            except ValueError:
                pass
            self.files_listbox.delete(idx)
        # prune gallery by label match
        kept_items = []
        new_photos = []
        for (frame, img_label, text_label) in self.thumb_items:
            label_text = text_label.cget("text")
            matched = False
            for name in names_to_remove:
                base = os.path.basename(name.replace("[URL] ", "")) if name.startswith("[URL] ") else os.path.basename(name)
                if label_text == base:
                    frame.destroy()
                    matched = True
                    break
            if not matched:
                kept_items.append((frame, img_label, text_label))
                new_photos.append(img_label.image)
        self.thumb_items = kept_items
        self.thumb_images = new_photos

    def clear_files(self):
        self.file_list.clear()
        self.files_listbox.delete(0, END)
        for frame, _, _ in self.thumb_items:
            frame.destroy()
        self.thumb_items.clear()
        self.thumb_images.clear()

    def add_url(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("URL", "Enter an image URL first.")
            return
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            messagebox.showerror("Invalid URL", "Please enter a valid HTTP/HTTPS URL.")
            return
        display = f"[URL] {url}"
        if display not in self.file_list:
            self.file_list.append(display)
            self.files_listbox.insert(END, display)
            self._build_thumb_from_url(url)
            self.url_var.set("")

    def pick_output_dir(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            if os.path.isfile(folder):
                messagebox.showerror("Output Folder", "Selected path is a file, not a folder.")
                return
            self.out_dir_var.set(folder)
            self.settings["output_dir"] = folder
            save_settings(self.settings)

    def start_compress(self):
        if not self.file_list:
            messagebox.showwarning("No Input", "Add at least one file or URL.")
            return
        out_dir = self.out_dir_var.get().strip()
        if not out_dir:
            messagebox.showwarning("Output Folder", "Select an output folder.")
            return
        try:
            if os.path.isfile(out_dir):
                raise OSError("Selected output path is a file, not a folder.")
            os.makedirs(out_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Output Folder", f"Could not create/use output folder: {e}")
            return

        out_fmt = self.format_var.get()
        try:
            q = int(self.quality_var.get())
        except Exception:
            q = 80
        quality = min(95, max(10, q))

        if self.resize_enable_var.get():
            max_w = int(self.width_var.get())
            max_h = int(self.height_var.get())
        else:
            max_w = max_h = 0

        # clear any stale tasks
        while not self.task_queue.empty():
            try:
                self.task_queue.get(False)
                self.task_queue.task_done()
            except queue.Empty:
                break

        total = 0
        for entry in self.file_list:
            if isinstance(entry, str) and entry.startswith("[URL] "):
                url = entry.replace("[URL] ", "", 1)
                self.task_queue.put((url, True, out_dir, out_fmt, quality, max_w, max_h))
                total += 1
            else:
                self.task_queue.put((entry, False, out_dir, out_fmt, quality, max_w, max_h))
                total += 1

        if total == 0:
            self._log("Nothing to process.", error=False)
            return

        self.total_tasks = total
        self.processed_count = 0
        self.log_entries = []
        self.progress.configure(value=0, maximum=self.total_tasks)

        self.start_btn.configure(state=DISABLED)
        self.cancel_btn.configure(state=NORMAL)
        self.stop_flag.clear()

        self._log(f"Starting compression of {total} item(s)...")

        status_cb = lambda msg, error=False, saved=False: self.root.after(0, self._handle_worker_message, msg, error, saved)
        done_cb = lambda: self.root.after(0, self._on_done)

        self.worker = CompressorWorker(
            task_queue=self.task_queue,
            status_callback=status_cb,
            done_callback=done_cb,
            stop_flag=self.stop_flag
        )
        self.worker.start()

    def cancel_compress(self):
        if self.worker and self.worker.is_alive():
            self.stop_flag.set()
            self._log("Cancelling... waiting for current item to finish.", error=False)

    def _on_done(self):
        self.start_btn.configure(state=NORMAL)
        self.cancel_btn.configure(state=DISABLED)
        out_dir = self.out_dir_var.get().strip()
        self.settings["output_dir"] = out_dir
        save_settings(self.settings)
        if self.stop_flag.is_set():
            self._log("Cancelled by user.")
        else:
            self._log("All done.")
        try:
            summary_path = os.path.join(out_dir, "compression_log.txt")
            with open(summary_path, "w", encoding="utf-8") as fh:
                fh.write("Pro Image Compressor - summary\n\n")
                for line, ok in self.log_entries:
                    fh.write(f"{'OK' if ok else 'FAIL'}\t{line}\n")
            self._log(f"Summary written to: {summary_path}")
        except Exception as e:
            self._log(f"Could not write summary log: {e}", error=True)

    def _handle_worker_message(self, msg: str, error: bool, saved: bool):
        self._log(msg, error=error)
        # count both saved and error so progress completes
        if saved or msg.startswith("Error"):
            self.processed_count += 1
            self.progress.configure(value=self.processed_count)
            self.log_entries.append((msg, saved))
        self.status_text.see(END)

    def _log(self, msg: str, error: bool = False):
        prefix = "ERROR: " if error else ""
        self.status_text.insert(END, f"{prefix}{msg}\n")
        self.status_text.see(END)

    # ---------------- Thumbnail Gallery -----------------
    def _make_thumbnail(self, pil_im: Image.Image) -> tk.PhotoImage:
        im = pil_im.copy()
        im.thumbnail(self.thumb_size, Image.LANCZOS)
        return ImageTk.PhotoImage(im)

    def _add_thumb_widget(self, display_name: str, pil_im: Image.Image):
        try:
            photo = self._make_thumbnail(pil_im)
        except Exception:
            return
        frame = tb.Frame(self.gallery_frame, padding=4)
        img_label = tb.Label(frame, image=photo)
        img_label.image = photo  # keep reference
        text_label = tb.Label(frame, text=os.path.basename(display_name), wraplength=120, justify="center")
        img_label.pack()
        text_label.pack(pady=(4, 0))
        frame.pack(side=tk.LEFT, padx=6, pady=6)
        self.thumb_images.append(photo)
        self.thumb_items.append((frame, img_label, text_label))

    def _enqueue_thumb_from_bytes(self, display_name: str, data: bytes):
        try:
            im = load_image_from_bytes(data)
        except Exception:
            return
        self.root.after(0, self._add_thumb_widget, display_name, im)

    def _build_thumb_from_file(self, path: str):
        try:
            with open(path, "rb") as f:
                data = f.read()
            threading.Thread(target=self._enqueue_thumb_from_bytes, args=(path, data), daemon=True).start()
        except Exception:
            pass

    def _build_thumb_from_url(self, url: str):
        def worker():
            try:
                data = fetch_image_from_url(url)
                self._enqueue_thumb_from_bytes(url, data)
            except Exception as e:
                self._log(f"Gallery: failed to fetch thumbnail for URL ({e})", error=True)
        threading.Thread(target=worker, daemon=True).start()

# ------------------ Entry Point ------------------
def main():
    root = TkinterDnD.Tk()
    app = ImageCompressorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
