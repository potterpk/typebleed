import struct
from .base import BaseParser, ParseResult

LOCAL_HEADER = b"\x50\x4b\x03\x04"
CENTRAL_DIR = b"\x50\x4b\x01\x02"
EOCD = b"\x50\x4b\x05\x06"


class ZIPParser(BaseParser):
    name = "ZIP"

    def parse(self, data: bytes) -> ParseResult:
        eocd_offset = data.rfind(EOCD)
        if eocd_offset == -1:
            return ParseResult(self.name, False)

        local_offset = data.find(LOCAL_HEADER)
        if local_offset == -1:
            return ParseResult(self.name, False)

        try:
            comment_len = struct.unpack("<H", data[eocd_offset + 20:eocd_offset + 22])[0]
        except struct.error:
            return ParseResult(self.name, False)

        end = eocd_offset + 22 + comment_len

        entries = []
        offset = local_offset
        while offset < len(data) - 4:
            if data[offset:offset + 4] != LOCAL_HEADER:
                break
            try:
                fname_len = struct.unpack("<H", data[offset + 26:offset + 28])[0]
                extra_len = struct.unpack("<H", data[offset + 28:offset + 30])[0]
                fname = data[offset + 30:offset + 30 + fname_len].decode("utf-8", errors="replace")
                entries.append(fname)
                compressed_size = struct.unpack("<I", data[offset + 18:offset + 22])[0]
                offset = offset + 30 + fname_len + extra_len + compressed_size
            except struct.error:
                break

        return ParseResult(
            self.name,
            valid=True,
            start=local_offset,
            end=end,
            details={"entries": entries, "prepended_bytes": local_offset},
        )
