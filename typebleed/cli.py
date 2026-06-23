import sys
from pathlib import Path
import click
from .detector import analyze
from .extractor import extract as do_extract
from .report import print_detection, print_json, console


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def main():
    """typebleed — polyglot file detector and extractor."""


@main.command("scan")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Only print polyglots, suppress clean files.")
@click.option("--recursive", "-r", is_flag=True, help="Recursively scan directories.")
@click.version_option(package_name="typebleed")
def scan(files, as_json, quiet, recursive):
    """Detect polyglot files in one or more paths.

    \b
    Examples:
      typebleed scan image.png
      typebleed scan uploads/ --recursive --quiet
      typebleed scan suspect.pdf --json
    """
    paths = _collect_paths(files, recursive)
    found = 0

    for path in paths:
        try:
            det = analyze(path)
        except Exception as e:
            console.print(f"[red]ERROR[/red] {path}: {e}")
            continue

        if as_json:
            print_json(det)
        elif det.is_polyglot:
            print_detection(det)
            found += 1
        elif not quiet:
            print_detection(det)

    if not as_json and found > 0:
        console.print(f"\n[bold red]{found} polyglot(s) detected.[/bold red]")

    sys.exit(1 if found > 0 else 0)


@main.command("extract")
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "fmt", default=None, help="Format to extract (e.g. ZIP, PDF). Defaults to all non-primary formats.")
@click.option("--all", "extract_all", is_flag=True, help="Extract every detected secondary format.")
@click.option("--out", "out_dir", default=None, type=click.Path(), help="Output directory (default: same as input file).")
@click.option("--dd", "show_dd", is_flag=True, help="Print the equivalent dd command instead of extracting.")
def extract(file, fmt, extract_all, out_dir, show_dd):
    """Extract a hidden format from a polyglot file.

    \b
    Examples:
      typebleed extract challenge.png
      typebleed extract challenge.png --format ZIP
      typebleed extract challenge.png --format ZIP --out ./loot/
      typebleed extract challenge.png --dd
    """
    path = Path(file)
    det = analyze(path)

    if not det.is_polyglot:
        console.print(f"[green]CLEAN[/green]  {path} — no polyglot detected, nothing to extract.")
        sys.exit(0)

    if show_dd:
        _print_dd_commands(path, det)
        sys.exit(0)

    dest = Path(out_dir) if out_dir else None
    if dest:
        dest.mkdir(parents=True, exist_ok=True)

    try:
        written = do_extract(path, fmt if not extract_all else None, dest)
    except ValueError as e:
        console.print(f"[red]ERROR[/red] {e}")
        sys.exit(2)

    if not written:
        console.print("[yellow]No secondary formats extracted.[/yellow]")
        sys.exit(0)

    for out_path in written:
        console.print(f"[green]EXTRACTED[/green]  {out_path}")


def _print_dd_commands(path: Path, det) -> None:
    data_len = path.stat().st_size
    primary = det.valid_formats[0]
    for result in det.valid_formats[1:]:
        skip = result.start
        count = result.end - result.start
        suffix = result.format_name.lower()
        out_name = f"{path.stem}.{suffix}.extracted"
        console.print(f"[cyan]# Extract {result.format_name} from {path.name}[/cyan]")
        console.print(f"dd if={path} of={out_name} bs=1 skip={skip} count={count}")


def _collect_paths(files: tuple, recursive: bool) -> list[Path]:
    paths = []
    for f in files:
        p = Path(f)
        if p.is_dir():
            if recursive:
                paths.extend(x for x in p.rglob("*") if x.is_file())
            else:
                console.print(f"[yellow]SKIP[/yellow]  {p} is a directory (use -r to recurse)")
        else:
            paths.append(p)
    return paths
