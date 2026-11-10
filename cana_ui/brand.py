"""
brand.py
========

CANA application mark used by the window, tray, and installer.

The mark is the official CANA blue feather. It is shipped as a
high-resolution PNG source (``cana-source.png``) and scaled to the sizes
needed by the title bar, taskbar, navigation header, tray, and installer.
Nothing here redraws or restyles the feather: every size is a resampling
of the same source art so it stays sharp and centered at 16-256 px with a
transparent background.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Optional, Sequence, Tuple

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
ICON_PNG = ASSETS_DIR / "cana.png"
ICON_ICO = ASSETS_DIR / "cana.ico"
ICON_SOURCE = ASSETS_DIR / "cana-source.png"

# Sizes written to disk for the frozen EXE, installer, and Start Menu.
ICON_SIZES: Tuple[int, ...] = (16, 32, 48, 256)


def _decode_png_rgba(data: bytes) -> Tuple[int, int, bytearray]:
    """Minimal 8-bit RGBA PNG decoder (all filter types, no interlace)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos = 8
    width = height = 0
    bit_depth = 8
    color_type = 6
    interlace = 0
    idat = bytearray()
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        tag = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if tag == b"IHDR":
            width, height, bit_depth, color_type, _comp, _filt, interlace = struct.unpack(
                ">IIBBBBB", chunk
            )
        elif tag == b"IDAT":
            idat.extend(chunk)
        elif tag == b"IEND":
            break
    if bit_depth != 8 or color_type != 6 or interlace != 0:
        raise ValueError("unsupported PNG format")

    raw = zlib.decompress(bytes(idat))
    stride = width * 4
    out = bytearray(height * stride)
    previous = bytearray(stride)
    offset = 0
    for y in range(height):
        filter_type = raw[offset]
        offset += 1
        line = bytearray(raw[offset : offset + stride])
        offset += stride
        if filter_type == 1:
            for i in range(4, stride):
                line[i] = (line[i] + line[i - 4]) & 0xFF
        elif filter_type == 2:
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 0xFF
        elif filter_type == 3:
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif filter_type == 4:
            for i in range(stride):
                left = line[i - 4] if i >= 4 else 0
                up = previous[i]
                up_left = previous[i - 4] if i >= 4 else 0
                est = left + up - up_left
                pa = abs(est - left)
                pb = abs(est - up)
                pc = abs(est - up_left)
                if pa <= pb and pa <= pc:
                    pred = left
                elif pb <= pc:
                    pred = up
                else:
                    pred = up_left
                line[i] = (line[i] + pred) & 0xFF
        out[y * stride : (y + 1) * stride] = line
        previous = line
    return width, height, out


def _scale_nearest(
    pixels: bytes, width: int, height: int, size: int
) -> bytes:
    """Nearest-neighbour downscale of RGBA pixels to ``size`` x ``size``."""
    out = bytearray(size * size * 4)
    for y in range(size):
        src_y = min(height - 1, (y * height) // size)
        for x in range(size):
            src_x = min(width - 1, (x * width) // size)
            src = (src_y * width + src_x) * 4
            dst = (y * size + x) * 4
            out[dst : dst + 4] = pixels[src : src + 4]
    return bytes(out)


def _load_source_image():
    """Return a square RGBA Pillow image of the feather, or ``None``."""
    try:
        from PIL import Image
    except Exception:  # noqa: BLE001
        return None
    source = ICON_SOURCE if ICON_SOURCE.is_file() else ICON_PNG
    if not source.is_file():
        return None
    try:
        image = Image.open(source).convert("RGBA")
    except Exception:  # noqa: BLE001
        return None
    return _square(image)


def _square(image):
    """Trim transparent margins and pad to a centered square."""
    from PIL import Image

    alpha = image.getchannel("A")
    bbox = alpha.getbbox()
    if bbox:
        image = image.crop(bbox)
    width, height = image.size
    side = max(width, height)
    pad = int(side * 0.10)
    side += pad * 2
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    canvas.paste(image, ((side - width) // 2, (side - height) // 2), image)
    return canvas


def render_mark(size: int) -> bytes:
    """Raw RGBA pixels of the CANA feather at ``size`` x ``size``."""
    image = _load_source_image()
    if image is not None:
        try:
            from PIL import Image

            resized = image.resize((size, size), Image.Resampling.LANCZOS)
            return resized.tobytes()
        except Exception:  # noqa: BLE001
            pass
    if not ICON_PNG.is_file():
        try:
            write_icon_assets()
        except Exception:  # noqa: BLE001
            pass
    if ICON_PNG.is_file():
        width, height, pixels = _decode_png_rgba(ICON_PNG.read_bytes())
        return _scale_nearest(pixels, width, height, size)
    raise RuntimeError("CANA feather asset is missing")


def write_icon_assets(directory: Optional[Path] = None) -> Tuple[Path, Path]:
    """Regenerate ``cana.png`` and a multi-size ICO from the feather source."""
    folder = Path(directory) if directory is not None else ASSETS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    png_path = folder / "cana.png"
    ico_path = folder / "cana.ico"

    image = _load_source_image()
    if image is None:
        return png_path, ico_path

    from PIL import Image

    base = image.resize((256, 256), Image.Resampling.LANCZOS)
    base.save(png_path, format="PNG", optimize=True)
    base.save(ico_path, format="ICO", sizes=[(size, size) for size in ICON_SIZES])
    for size in ICON_SIZES:
        image.resize((size, size), Image.Resampling.LANCZOS).save(
            folder / f"cana-{size}.png", format="PNG", optimize=True
        )
    return png_path, ico_path


def apply_window_icon(root) -> None:
    """Attach the CANA feather to a Tk root (title bar and taskbar)."""
    if not ICON_PNG.is_file():
        try:
            write_icon_assets()
        except Exception:  # noqa: BLE001
            return
    try:
        import tkinter as tk

        photo = tk.PhotoImage(file=str(ICON_PNG))
        root._cana_icon_photo = photo
        root.iconphoto(True, photo)
    except Exception:  # noqa: BLE001
        pass
    if ICON_ICO.is_file():
        try:
            root.iconbitmap(str(ICON_ICO))
        except Exception:  # noqa: BLE001
            pass


def header_photo(size: int = 20):
    """Small Tk image of the feather for the navigation/header brand."""
    if not ICON_PNG.is_file():
        try:
            write_icon_assets()
        except Exception:  # noqa: BLE001
            return None
    try:
        from PIL import Image, ImageTk

        image = _load_source_image()
        if image is None:
            image = Image.open(ICON_PNG).convert("RGBA")
        resized = image.resize((size, size), Image.Resampling.LANCZOS)
        return ImageTk.PhotoImage(resized)
    except Exception:  # noqa: BLE001
        pass
    try:
        import tkinter as tk

        photo = tk.PhotoImage(file=str(ICON_PNG))
        factor = max(1, photo.width() // max(1, size))
        return photo.subsample(factor, factor)
    except Exception:  # noqa: BLE001
        return None


def tray_image():
    """RGBA image for the system tray. Uses Pillow when present."""
    if not ICON_PNG.is_file():
        try:
            write_icon_assets()
        except Exception:  # noqa: BLE001
            pass
    try:
        from PIL import Image

        if ICON_PNG.is_file():
            return Image.open(ICON_PNG).convert("RGBA")
    except Exception:  # noqa: BLE001
        pass
    try:
        from PIL import Image

        return Image.frombytes("RGBA", (64, 64), render_mark(64))
    except Exception:  # noqa: BLE001
        return None


__all__ = [
    "ASSETS_DIR",
    "ICON_ICO",
    "ICON_PNG",
    "ICON_SIZES",
    "ICON_SOURCE",
    "apply_window_icon",
    "header_photo",
    "render_mark",
    "tray_image",
    "write_icon_assets",
]
