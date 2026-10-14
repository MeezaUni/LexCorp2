"""Safe parsing of untrusted uploaded files: XML, ZIP containers (OOXML), images and PDFs.

Every copy that comes back (revision uploads, the verify pages, tamper evidence) is
attacker-controlled. These helpers bound what parsing it can cost and refuse the classic
tricks: XML external entities and entity expansion, ZIP bombs and path-traversal entry
names, decompression-bomb images and PDFs with absurd page counts.
"""

from __future__ import annotations

import itertools
import zipfile
from typing import Iterable, Iterator

MAX_ZIP_ENTRIES = 500
MAX_ZIP_UNCOMPRESSED = 100 * 1024 * 1024     # 100 MB, declared uncompressed total
MAX_IMAGE_PIXELS = 25_000_000                 # Pillow warns above this and refuses above twice it
MAX_PDF_PAGES = 200


class UnsafeFile(ValueError):
    """The file is outside the limits LexCorp will parse."""


def _xml_parser():
    from lxml import etree
    return etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False,
                           load_dtd=False, huge_tree=False)


def safe_xml_fromstring(data: bytes):
    """lxml.etree.fromstring without entity resolution, DTD loading, network access or huge trees."""
    from lxml import etree
    return etree.fromstring(data, _xml_parser())


def validate_safe_zip(z: zipfile.ZipFile, max_entries: int = MAX_ZIP_ENTRIES,
                      max_uncompressed_bytes: int = MAX_ZIP_UNCOMPRESSED) -> zipfile.ZipFile:
    """Refuse archives with too many entries, too much declared content or unsafe entry names.

    zipfile stops reading an entry at its declared size (and checks its CRC), so the declared
    total bounds what reading every entry can decompress."""
    infos = z.infolist()
    if len(infos) > max_entries:
        raise UnsafeFile(f"archive has {len(infos)} entries (limit {max_entries})")
    if sum(i.file_size for i in infos) > max_uncompressed_bytes:
        raise UnsafeFile("archive expands beyond the allowed size")
    for i in infos:
        name = i.filename
        if ".." in name.replace("\\", "/").split("/") or name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
            raise UnsafeFile(f"unsafe archive entry name: {name[:80]!r}")
    return z


def open_safe_zip(data_or_file) -> zipfile.ZipFile:
    """zipfile.ZipFile(...) for reading an untrusted archive, validated before any entry is read."""
    z = zipfile.ZipFile(data_or_file)
    try:
        return validate_safe_zip(z)
    except Exception:
        z.close()
        raise


def configure_pillow() -> None:
    """Pillow raises DecompressionBombError for images over twice this many pixels."""
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


def limited_pages(pages: Iterable, limit: int = MAX_PDF_PAGES) -> Iterator:
    """At most `limit` pages of a PDF (a hostile file may declare thousands)."""
    return itertools.islice(pages, limit)
