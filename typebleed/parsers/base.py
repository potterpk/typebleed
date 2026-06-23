from dataclasses import dataclass, field
from abc import ABC, abstractmethod


@dataclass
class ParseResult:
    format_name: str
    valid: bool
    start: int = 0
    end: int = 0
    details: dict = field(default_factory=dict)


class BaseParser(ABC):
    name: str = ""

    @abstractmethod
    def parse(self, data: bytes) -> ParseResult:
        ...
