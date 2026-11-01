"""RGB565 framebuffer -> PNG renderer for the LCD model (240x320).

Uses PIL when available; otherwise a pure struct/zlib PNG writer (no other
dependency). Function: render_png(frame_bytes, path, width=240, height=320).
"""
import struct
import zlib

try:
    from PIL import Image
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False


def rgb565_to_rgb888(frame, width=240, height=320):
    """Convert an RGB565 little-endian buffer to packed RGB888 bytes.
    Pads short buffers with black so a partial frame still renders."""
    n = width * height
    if len(frame) < n * 2:
        frame = bytes(frame) + bytes(n * 2 - len(frame))
    px = struct.unpack_from("<%dH" % n, frame)
    out = bytearray(n * 3)
    j = 0
    for v in px:
        r = (v >> 11) & 0x1F
        g = (v >> 5) & 0x3F
        b = v & 0x1F
        out[j] = (r << 3) | (r >> 2)
        out[j + 1] = (g << 2) | (g >> 4)
        out[j + 2] = (b << 3) | (b >> 2)
        j += 3
    return bytes(out)


def _write_png_manual(rgb, width, height, path):
    """Minimal PNG encoder: 8-bit truecolor, one filter-0 row per line."""
    stride = width * 3
    raw = bytearray()
    for y in range(height):
        raw.append(0)                       # filter type 0 (None)
        raw += rgb[y * stride:(y + 1) * stride]

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = (b"\x89PNG\r\n\x1a\n" +
           chunk(b"IHDR", ihdr) +
           chunk(b"IDAT", zlib.compress(bytes(raw), 6)) +
           chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)


def render_png(frame_bytes, path, width=240, height=320):
    """Write frame_bytes (RGB565, row-major, width*height pixels) as a PNG."""
    rgb = rgb565_to_rgb888(frame_bytes, width, height)
    if HAVE_PIL:
        Image.frombytes("RGB", (width, height), rgb).save(path)
    else:
        _write_png_manual(rgb, width, height, path)
    return path


if __name__ == "__main__":
    # self-test: red/green/blue horizontal bars -> _test.png
    w, h = 240, 320
    fb = bytearray(w * h * 2)
    for y in range(h):
        for x in range(w):
            v = 0xF800 if y < h // 3 else (0x07E0 if y < 2 * h // 3 else 0x001F)
            struct.pack_into("<H", fb, (y * w + x) * 2, v)
    render_png(bytes(fb), "_test.png", w, h)
    print("wrote _test.png (PIL=%s)" % HAVE_PIL)
