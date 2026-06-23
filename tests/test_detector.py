import subprocess
import sys
from pathlib import Path
import pytest

POLYGLOTS = Path(__file__).parent / "polyglots"


@pytest.fixture(scope="session", autouse=True)
def build_polyglots():
    subprocess.run([sys.executable, str(Path(__file__).parent / "make_polyglots.py")], check=True)


def _analyze(filename):
    from typebleed.detector import analyze
    return analyze(POLYGLOTS / filename)


def test_png_zip_is_polyglot():
    det = _analyze("png_zip.png")
    assert det.is_polyglot
    formats = {r.format_name for r in det.valid_formats}
    assert "PNG" in formats
    assert "ZIP" in formats
    assert det.highest_severity == "HIGH"


def test_gif_php_is_polyglot():
    det = _analyze("gif_php.gif")
    assert det.is_polyglot
    formats = {r.format_name for r in det.valid_formats}
    assert "GIF" in formats


def test_jpeg_zip_is_polyglot():
    det = _analyze("jpeg_zip.jpg")
    assert det.is_polyglot
    formats = {r.format_name for r in det.valid_formats}
    assert "JPEG" in formats
    assert "ZIP" in formats


def test_svg_html_is_polyglot():
    det = _analyze("svg_html.svg")
    assert det.is_polyglot
    formats = {r.format_name for r in det.valid_formats}
    assert "SVG" in formats


def test_clean_png_not_polyglot():
    det = _analyze("clean.png")
    assert not det.is_polyglot
    assert det.highest_severity == "NONE"


def test_severity_escalation_with_active_content():
    det = _analyze("svg_html.svg")
    assert det.highest_severity in ("HIGH", "MEDIUM")
