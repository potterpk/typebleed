from .png import PNGParser
from .zip import ZIPParser
from .pdf import PDFParser
from .jpeg import JPEGParser
from .gif import GIFParser
from .svg import SVGParser
from .php import PHPParser
from .html import HTMLParser

ALL_PARSERS = [PNGParser, ZIPParser, PDFParser, JPEGParser, GIFParser, SVGParser, PHPParser, HTMLParser]
