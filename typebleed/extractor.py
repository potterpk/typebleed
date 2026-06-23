import struct
from pathlib import Path
from .detector import analyze
from .parsers.base import ParseResult

EOCD_SIG = b"\x50\x4b\x05\x06"


def extract(path: Path, fmt: str | None, out_dir: Path | None) -> list[Path]:
    det = analyze(path)

    if not det.is_polyglot:
        return []

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
    eocd = buf.rfind(EOCD_SIG)
    if eocd == -1:
        return buf

    try:
        cd_offset = struct.unpack_from("<I", buf, eocd + 16)[0]
        if cd_offset >= prepend:
            patched = cd_offset - prepend
            struct.pack_into("<I", buf, eocd + 16, patched)
    except struct.error:
        pass

    return buf
