import re
from .base import BaseParser, ParseResult

DOCTYPE = re.compile(rb"<!DOCTYPE\s+html", re.IGNORECASE)
HTML_OPEN = re.compile(rb"<html[\s>]", re.IGNORECASE)
HTML_CLOSE = re.compile(rb"</html>", re.IGNORECASE)


class HTMLParser(BaseParser):
    name = "HTML"

    def parse(self, data: bytes) -> ParseResult:
        doctype = DOCTYPE.search(data)
        html_open = HTML_OPEN.search(data)

        anchor = doctype or html_open
        if not anchor:
            return ParseResult(self.name, False)

        start = anchor.start()
        close = HTML_CLOSE.search(data)
        end = close.end() if close else len(data)

        has_script = bool(re.search(rb"<script", data, re.IGNORECASE))
        has_iframe = bool(re.search(rb"<iframe", data, re.IGNORECASE))
        has_svg = bool(re.search(rb"<svg[\s>]", data, re.IGNORECASE))

        return ParseResult(
            self.name,
            valid=True,
            start=start,
            end=end,
            details={
                "script_tag": has_script,
                "iframe": has_iframe,
                "embedded_svg": has_svg,
                "prepended_bytes": start,
            },
        )
