import re
from .base import BaseParser, ParseResult

PDF_MAGIC = b"%PDF-"
EOF_MARKER = b"%%EOF"


class PDFParser(BaseParser):
    name = "PDF"

    def parse(self, data: bytes) -> ParseResult:
        start = data.find(PDF_MAGIC)
        if start == -1:
            return ParseResult(self.name, False)

        eof_offset = data.rfind(EOF_MARKER)
        if eof_offset == -1:
            return ParseResult(self.name, False)

        end = eof_offset + len(EOF_MARKER)
        version_match = re.search(rb"%PDF-(\d+\.\d+)", data)
        version = version_match.group(1).decode() if version_match else "unknown"

        js_present = b"/JavaScript" in data or b"/JS" in data
        has_launch = b"/Launch" in data
        has_openaction = b"/OpenAction" in data

        return ParseResult(
            self.name,
            valid=True,
            start=start,
            end=end,
            details={
                "version": version,
                "javascript": js_present,
                "launch_action": has_launch,
                "open_action": has_openaction,
                "prepended_bytes": start,
            },
        )
