import re
from .base import BaseParser, ParseResult


class SVGParser(BaseParser):
    name = "SVG"

    def parse(self, data: bytes) -> ParseResult:
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return ParseResult(self.name, False)

        svg_open = re.search(r"<svg[\s>]", text, re.IGNORECASE)
        if not svg_open:
            return ParseResult(self.name, False)

        svg_close = text.rfind("</svg>")
        if svg_close == -1:
            return ParseResult(self.name, False)

        start = svg_open.start()
        end = svg_close + len("</svg>")

        has_script = bool(re.search(r"<script", text, re.IGNORECASE))
        has_onload = bool(re.search(r"\bon\w+\s*=", text, re.IGNORECASE))
        also_html = bool(re.search(r"<html[\s>]", text, re.IGNORECASE))

        return ParseResult(
            self.name,
            valid=True,
            start=start,
            end=end,
            details={
                "script_tag": has_script,
                "event_handlers": has_onload,
                "also_html": also_html,
                "prepended_bytes": start,
            },
        )
