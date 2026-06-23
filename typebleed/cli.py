import sys
from pathlib import Path
import click
from .detector import analyze
from .report import print_detection, print_json, console


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Only print polyglots, suppress clean files.")
@click.version_option(package_name="typebleed")
def main(files, as_json, quiet):
    """Detect polyglot files that are simultaneously valid in multiple formats.

    These files are used to bypass file upload validators and WAF filters.

    \b
    Examples:
      typebleed image.png
      typebleed uploads/* --quiet
      typebleed suspect.pdf --json
    """
    found = 0
    for path_str in files:
        path = Path(path_str)
        if not path.is_file():
            console.print(f"[dim]Skipping {path} (not a file)[/dim]")
            continue

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
