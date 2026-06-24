from dataclasses import dataclass
from .parsers.base import ParseResult


@dataclass
class Overlap:
    format_a: str
    format_b: str
    overlap_start: int
    overlap_end: int
    overlap_bytes: int
    kind: str  # "header", "appended", "nested"


def classify_overlap(a: ParseResult, b: ParseResult) -> Overlap | None:
    overlap_start = max(a.start, b.start)
    overlap_end = min(a.end, b.end)

    if overlap_end > overlap_start:
        a_in_b = a.start >= b.start and a.end <= b.end
        b_in_a = b.start >= a.start and b.end <= a.end
        kind = "nested" if (a_in_b or b_in_a) else "header"
        return Overlap(
            format_a=a.format_name,
            format_b=b.format_name,
            overlap_start=overlap_start,
            overlap_end=overlap_end,
            overlap_bytes=overlap_end - overlap_start,
            kind=kind,
        )

    if b.start >= a.end:
        return Overlap(
            format_a=a.format_name,
            format_b=b.format_name,
            overlap_start=b.start,
            overlap_end=b.end,
            overlap_bytes=b.end - b.start,
            kind="appended",
        )

    if a.start >= b.end:
        return Overlap(
            format_a=b.format_name,
            format_b=a.format_name,
            overlap_start=a.start,
            overlap_end=a.end,
            overlap_bytes=a.end - a.start,
            kind="appended",
        )

    return None


SEVERITY_MAP = {
    "header": "HIGH",
    "nested": "MEDIUM",
    "appended": "LOW",
}


def score_severity(overlap: Overlap, details_a: dict, details_b: dict) -> str:
    base = SEVERITY_MAP[overlap.kind]

    # Escalate appended if one format explicitly validates trailing bytes (ZIP does)
    if base == "LOW" and "ZIP" in (overlap.format_a, overlap.format_b):
        base = "HIGH"

    # Escalate if active content detected
    active_flags = ["javascript", "php_code_present", "script_tag", "event_handlers",
                    "launch_action", "open_action"]
    combined = {**details_a, **details_b}
    if any(combined.get(f) for f in active_flags):
        if base == "LOW":
            base = "MEDIUM"
        elif base == "MEDIUM":
            base = "HIGH"

    return base
