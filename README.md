# typebleed

A static analysis tool that detects polyglot files — files simultaneously valid in multiple formats — used to bypass file upload validators and WAF filters.

---

## What is a polyglot file?

A polyglot file is one that two different format parsers both accept as their own. The classic attack: you upload `evil.png` to a web app. The server checks the magic bytes at the start, sees `\x89PNG`, says "it's an image, allow it." But the file was crafted so that a ZIP reader can also open it — because the ZIP is hiding after the PNG ends, and ZIP readers scan from the *back* of the file. One file. Two valid formats. The upload check passes. The ZIP payload gets in.

`typebleed` finds these files before they become your problem.

---

## Supported format pairs

| Format A | Format B | Attack scenario |
|---|---|---|
| PNG | ZIP | Upload bypass — image validator passes, ZIP payload executes |
| JPEG | ZIP | Same — JPEG EOI marker hides appended ZIP |
| GIF | PHP | Web shell bypass — GIF header fools MIME check, PHP executes |
| SVG | HTML | XSS via SVG event handlers in an HTML document |
| PDF | — | Flags embedded JavaScript, `/Launch`, `/OpenAction` actions |
| Any | PHP | PHP code appended or embedded after any valid format |

---

## Install

```bash
git clone https://github.com/potterpk/typebleed.git
cd typebleed
pip install -e .
```

Requires Python 3.10+.

---

## Usage

### Scan files

```bash
typebleed scan image.png
typebleed scan uploads/          # directory (non-recursive)
typebleed scan uploads/ -r       # recursive
typebleed scan uploads/ -r -q    # quiet — only print hits, skip clean files
typebleed scan suspect.pdf --json | jq .
```

Example output:

```
[!] POLYGLOT DETECTED — HIGH
    File : uploads/profile.png
    Size : 198 bytes
    Valid formats : PNG, ZIP

  Format A   Format B   Type       Overlap offset          Bytes   Severity
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PNG        ZIP        appended   0x00000045–0x000000c6   129     HIGH

CLEAN  uploads/avatar.png

1 polyglot(s) detected.
```

Exit code is `1` if any polyglots are found, `0` if everything is clean — so it plugs straight into CI:

```bash
typebleed scan uploads/ -r -q || echo "polyglot detected, failing build"
```

---

### Extract the hidden format

Once you know a file is a polyglot, pull the hidden format out:

```bash
typebleed extract challenge.png
# writes: challenge.png.zip.extracted

typebleed extract challenge.png --format ZIP
typebleed extract challenge.png --all          # extract every secondary format
typebleed extract challenge.png --out ./loot/  # write to a specific directory
```

If you're on a machine without typebleed, get the raw `dd` command instead:

```bash
typebleed extract challenge.png --dd
# prints: dd if=challenge.png of=challenge.zip.extracted bs=1 skip=69 count=129
```

---

## CTF usage

Got a suspicious file in a forensics challenge?

```bash
# check if it's a polyglot
typebleed scan challenge.file

# pull out the hidden format
typebleed extract challenge.file

# work with what you extracted
unzip challenge.file.zip.extracted
strings challenge.file.php.extracted
```

The `--dd` flag is useful when you're inside a CTF environment and can't install tools — copy the printed command and run it anywhere.

---

## Adding a parser

Each format is a single file in `typebleed/parsers/`. A parser reads raw bytes and returns where in the file its format lives:

```python
from .base import BaseParser, ParseResult

class MP3Parser(BaseParser):
    name = "MP3"

    def parse(self, data: bytes) -> ParseResult:
        if not (data.startswith(b"\xff\xfb") or data.startswith(b"ID3")):
            return ParseResult(self.name, False)
        # find the end of the audio data...
        return ParseResult(self.name, valid=True, start=0, end=end)
```

Then register it in `typebleed/parsers/__init__.py`:

```python
from .mp3 import MP3Parser
ALL_PARSERS = [..., MP3Parser]
```

The detector, analyzer, and CLI pick it up automatically.

---

## Run tests

```bash
pip install pytest
pytest tests/ -v
```

The test suite generates real polyglot files from scratch and verifies detection and extraction for each format pair.

---

## License

MIT
