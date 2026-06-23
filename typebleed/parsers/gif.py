from .base import BaseParser, ParseResult

GIF_MAGIC = (b"GIF87a", b"GIF89a")
GIF_TRAILER = b"\x3b"


class GIFParser(BaseParser):
    name = "GIF"

    def parse(self, data: bytes) -> ParseResult:
        matched = next((m for m in GIF_MAGIC if data.startswith(m)), None)
        if not matched:
            return ParseResult(self.name, False)

        trailer = data.rfind(GIF_TRAILER)
        if trailer == -1:
            return ParseResult(self.name, False)

        end = trailer + 1
        version = matched.decode()
        trailing = len(data) - end

        php_pattern = b"<?php"
        has_php = php_pattern in data

        return ParseResult(
            self.name,
            valid=True,
            start=0,
            end=end,
            details={
                "version": version,
                "trailing_bytes": trailing,
                "php_code_present": has_php,
            },
        )
