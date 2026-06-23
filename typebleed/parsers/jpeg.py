from .base import BaseParser, ParseResult

JPEG_MAGIC = b"\xff\xd8\xff"
JPEG_EOI = b"\xff\xd9"


class JPEGParser(BaseParser):
    name = "JPEG"

    def parse(self, data: bytes) -> ParseResult:
        if not data.startswith(JPEG_MAGIC):
            return ParseResult(self.name, False)

        eoi = data.rfind(JPEG_EOI)
        if eoi == -1:
            return ParseResult(self.name, False)

        end = eoi + 2
        trailing = len(data) - end

        return ParseResult(
            self.name,
            valid=True,
            start=0,
            end=end,
            details={"trailing_bytes": trailing},
        )
