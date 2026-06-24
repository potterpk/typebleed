from .base import BaseParser, ParseResult

PHP_OPEN = b"<?php"
PHP_ECHO = b"<?="


class PHPParser(BaseParser):
    name = "PHP"

    def parse(self, data: bytes) -> ParseResult:
        start = data.find(PHP_OPEN)
        if start == -1:
            start = data.find(PHP_ECHO)
            if start == -1:
                return ParseResult(self.name, False)

        close_tag = data.find(b"?>", start)
        end = close_tag + 2 if close_tag != -1 else len(data)

        has_shell = b"shell_exec" in data or b"system(" in data or b"passthru" in data
        has_eval = b"eval(" in data
        has_base64 = b"base64_decode" in data

        return ParseResult(
            self.name,
            valid=True,
            start=start,
            end=end,
            details={
                "shell_exec": has_shell,
                "eval": has_eval,
                "base64_decode": has_base64,
                "prepended_bytes": start,
            },
        )
