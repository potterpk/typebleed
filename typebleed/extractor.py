import struct
from pathlib import Path
from .detector import analyze, Detection
from .parsers.base import ParseResult

EOCD_SIG = b"\x50\x4b\x05\x06"
CENTRAL_SIG = b"\x50\x4b\x01\x02"
LOCAL_SIG = b"\x50\x4b\x03\x04"


def extract(path: Path, det: Detection, fmt: str | None, out_dir: Path | None) -> list[Path]:
    targets: list[ParseResult] = []

    if fmt:
        fmt_upper = fmt.upper()
        targets = [r for r in det.valid_formats if r.format_name == fmt_upper]
        if not targets:
            available = ", ".join(r.format_name for r in det.valid_formats)
            raise ValueError(f"Format {fmt_upper!r} not detected in file. Found: {available}")
    else:
        primary = det.valid_formats[0]
        targets = [r for r in det.valid_formats if r != primary]

    data = path.read_bytes()
    dest = out_dir or path.parent
    written: list[Path] = []

    for result in targets:
        chunk = data[result.start:result.end]
        if result.format_name == "ZIP" and result.start > 0:
            chunk = _patch_zip_offsets(chunk, result.start)
        suffix = result.format_name.lower()
        out_path = dest / f"{path.stem}.{suffix}.extracted"
        out_path.write_bytes(chunk)
        written.append(out_path)

    return written


def _patch_zip_offsets(data: bytes, prepend: int) -> bytearray:
    buf = bytearray(data)

    # Patch local header offsets in every central directory entry
    offset = 0
    while offset < len(buf) - 4:
        if buf[offset:offset + 4] != CENTRAL_SIG:
            offset += 1
            continue
        try:
            fname_len = struct.unpack_from("<H", buf, offset + 28)[0]
            extra_len = struct.unpack_from("<H", buf, offset + 30)[0]
            comment_len = struct.unpack_from("<H", buf, offset + 32)[0]
            local_offset = struct.unpack_from("<I", buf, offset + 42)[0]
            if local_offset >= prepend:
                struct.pack_into("<I", buf, offset + 42, local_offset - prepend)
            offset += 46 + fname_len + extra_len + comment_len
        except struct.error:
            break

    # Patch the central directory start offset in EOCD
    eocd = buf.rfind(EOCD_SIG)
    if eocd != -1:
        try:
            cd_offset = struct.unpack_from("<I", buf, eocd + 16)[0]
            if cd_offset >= prepend:
                struct.pack_into("<I", buf, eocd + 16, cd_offset - prepend)
        except struct.error:
            pass

    return buf
