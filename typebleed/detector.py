from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path

from .parsers import ALL_PARSERS
from .parsers.base import ParseResult
from .analyzer import Overlap, classify_overlap, score_severity


@dataclass
class Detection:
    file: str
    size: int
    valid_formats: list[ParseResult]
    overlaps: list[Overlap]
    severities: list[str]
    is_polyglot: bool

    @property
    def highest_severity(self) -> str:
        order = ["HIGH", "MEDIUM", "LOW"]
        for s in order:
            if s in self.severities:
                return s
        return "NONE"


def analyze(path: Path) -> Detection:
    data = path.read_bytes()
    results = [p().parse(data) for p in ALL_PARSERS]
    valid = [r for r in results if r.valid]

    overlaps = []
    severities = []

    for a, b in combinations(valid, 2):
        overlap = classify_overlap(a, b)
        if overlap:
            sev = score_severity(overlap, a.details, b.details)
            overlaps.append(overlap)
            severities.append(sev)

    return Detection(
        file=str(path),
        size=len(data),
        valid_formats=valid,
        overlaps=overlaps,
        severities=severities,
        is_polyglot=len(valid) >= 2 and len(overlaps) > 0,
    )
