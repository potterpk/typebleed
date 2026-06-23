import struct
from .base import BaseParser, ParseResult

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
IEND_CHUNK = b"IEND"


class PNGParser(BaseParser):
    name = "PNG"

    def parse(self, data: bytes) -> ParseResult:
        if not data.startswith(PNG_MAGIC):
            return ParseResult(self.name, False)

        offset = 8
        end = len(data)
        chunks = []

        while offset + 12 <= len(data):
            try:
                length = struct.unpack(">I", data[offset:offset + 4])[0]
                chunk_type = data[offset + 4:offset + 8]
                chunks.append(chunk_type.decode("ascii", errors="replace"))
                chunk_end = offset + 12 + length
                if chunk_type == IEND_CHUNK:
                    end = chunk_end
                    break
                offset = chunk_end
            except struct.error:
                break

        return ParseResult(
            self.name,
            valid=True,
            start=0,
            end=end,
            details={"chunks": chunks},
        )
