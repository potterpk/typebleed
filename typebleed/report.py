import json
from rich.console import Console
from rich.table import Table
from rich import box
from .detector import Detection

console = Console()

SEVERITY_COLOR = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "NONE": "dim",
}


def print_detection(det: Detection) -> None:
    if not det.is_polyglot:
        console.print(f"[green]CLEAN[/green]  {det.file}")
        return

    sev_color = SEVERITY_COLOR[det.highest_severity]
    console.print(f"\n[{sev_color}][!] POLYGLOT DETECTED — {det.highest_severity}[/{sev_color}]")
    console.print(f"    File : {det.file}")
    console.print(f"    Size : {det.size:,} bytes")

    formats = ", ".join(r.format_name for r in det.valid_formats)
    console.print(f"    Valid formats : {formats}\n")

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold white")
    table.add_column("Format A", style="cyan")
    table.add_column("Format B", style="cyan")
    table.add_column("Type", style="white")
    table.add_column("Overlap offset", style="white")
    table.add_column("Bytes", style="white")
    table.add_column("Severity", style="white")

    for overlap, sev in zip(det.overlaps, det.severities):
        table.add_row(
            overlap.format_a,
            overlap.format_b,
            overlap.kind,
            f"0x{overlap.overlap_start:08x}–0x{overlap.overlap_end:08x}",
            str(overlap.overlap_bytes),
            f"[{SEVERITY_COLOR[sev]}]{sev}[/{SEVERITY_COLOR[sev]}]",
        )

    console.print(table)

    for r in det.valid_formats:
        if r.details:
            _print_details(r.format_name, r.details)


def _print_details(name: str, details: dict) -> None:
    active_flags = {
        "javascript": "JavaScript actions present — active content",
        "php_code_present": "PHP code detected in file body",
        "script_tag": "SVG <script> tag — XSS vector",
        "event_handlers": "SVG event handlers (onload etc.) — XSS vector",
        "launch_action": "PDF /Launch action — execution risk",
        "open_action": "PDF /OpenAction — execution risk",
    }
    warnings = [msg for key, msg in active_flags.items() if details.get(key)]
    if warnings:
        console.print(f"    [bold yellow][{name}][/bold yellow]")
        for w in warnings:
            console.print(f"      [yellow]⚠[/yellow]  {w}")


def print_json(det: Detection) -> None:
    out = {
        "file": det.file,
        "size": det.size,
        "is_polyglot": det.is_polyglot,
        "highest_severity": det.highest_severity,
        "valid_formats": [
            {"format": r.format_name, "start": r.start, "end": r.end, "details": r.details}
            for r in det.valid_formats
        ],
        "overlaps": [
            {
                "format_a": o.format_a,
                "format_b": o.format_b,
                "kind": o.kind,
                "overlap_start": o.overlap_start,
                "overlap_end": o.overlap_end,
                "overlap_bytes": o.overlap_bytes,
                "severity": s,
            }
            for o, s in zip(det.overlaps, det.severities)
        ],
    }
    print(json.dumps(out, indent=2))
