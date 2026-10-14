"""Untrusted-file parsing limits: XXE, entity expansion, ZIP bombs, traversal names, image bombs."""

import io
import zipfile

import pytest

from app.core.safe_files import MAX_PDF_PAGES, UnsafeFile, limited_pages, open_safe_zip, safe_xml_fromstring
from app.services import hidden_mark
from app.services.watermark import UnsupportedDocumentType, detect_type
from app.services.watermark_strip import _resolve


def _zip(entries: dict) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return out.getvalue()


def test_external_entities_are_not_resolved(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET")
    xml = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///{secret.as_posix()}">]><r>&x;</r>'.encode()
    root = safe_xml_fromstring(xml)
    assert "TOP-SECRET" not in (root.text or "")


def test_entity_expansion_bomb_is_not_expanded():
    lol = "".join(f'<!ENTITY l{i} "{("&l%d;" % (i - 1)) * 10}">' for i in range(1, 9))
    xml = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY l0 "lol">{lol}]><r>&l8;</r>'.encode()
    from lxml import etree
    try:
        root = safe_xml_fromstring(xml)
    except etree.XMLSyntaxError:
        return  # refused outright (libxml2's amplification limit)
    assert len(root.text or "") < 1000


def test_zip_bomb_and_too_many_entries_refused():
    bomb = _zip({"[Content_Types].xml": "<x/>", "word/document.xml": b"\0" * (101 * 1024 * 1024)})
    with pytest.raises(UnsafeFile):
        open_safe_zip(io.BytesIO(bomb))
    many = _zip({f"f{i}.xml": "" for i in range(501)})
    with pytest.raises(UnsafeFile):
        open_safe_zip(io.BytesIO(many))
    # an upload like this is refused as an unsupported document, not a server error
    with pytest.raises(UnsupportedDocumentType):
        detect_type(bomb, "x.docx")


@pytest.mark.parametrize("name", ["../evil.xml", "word/../../evil.xml", "/abs.xml", "\\abs.xml", "C:/x.xml"])
def test_traversal_entry_names_refused(name):
    with pytest.raises(UnsafeFile):
        open_safe_zip(io.BytesIO(_zip({"[Content_Types].xml": "<x/>", name: "x"})))


def test_dotted_but_safe_names_allowed():
    z = open_safe_zip(io.BytesIO(_zip({"[Content_Types].xml": "<x/>", "word/media/a..b.png": "x"})))
    assert "word/media/a..b.png" in z.namelist()


def test_hostile_ooxml_never_crashes_mark_reading():
    hostile = _zip({"[Content_Types].xml": "<x/>", "docProps/custom.xml":
                    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'})
    assert hidden_mark.read_marks(hostile) == []
    assert hidden_mark.remove_ooxml(_zip({"../x": "y"}), {}) is not None


def test_relationship_target_cannot_climb_above_the_root():
    assert _resolve("xl/worksheets/sheet1.xml", "../../../../x.xml") == "x.xml"


def test_image_bomb_refused():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("1", (10_000, 6_000)).save(buf, format="PNG")    # 60 M pixels, tiny file
    with pytest.raises(Image.DecompressionBombError):
        Image.open(io.BytesIO(buf.getvalue())).load()
    assert hidden_mark.read_marks(buf.getvalue()) == []


def test_pdf_pages_are_capped():
    assert len(list(limited_pages(range(10_000)))) == MAX_PDF_PAGES
