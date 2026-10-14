"""Invisible copy marks: a second, hidden identifier inside every protected copy.

The visible watermark can be edited to point at someone else's record. Each issued copy also
carries a random 64-bit mark (16 hex characters) that a reader of the copy can't see, stored on
the copy's action record (DocumentAction.hidden_mark). Verification reads it back and checks
that it belongs to the record the copy claims; if it belongs to a different copy, that copy's
record says who it was really issued to. Only Auditors are shown that this check exists.

  PDF    invisible text (render mode 3) inside the per-page watermark layer
  Image  a row of faint blocks along the bottom edge of the footer band
  Office a custom document property whose name starts with "_", which Office hides

Every placement sits inside a layer the watermark strip already removes, or is removed with it.
"""

from __future__ import annotations

import io
import re
import secrets
import zipfile
from typing import Optional
from app.core.safe_files import UnsafeFile, configure_pillow, limited_pages, open_safe_zip, safe_xml_fromstring

configure_pillow()

_HEX16 = re.compile(r"^[0-9a-f]{16}$")


def new_mark() -> str:
    return secrets.token_hex(8)


# ------------------------------------------------------------------ image band

_SYNC = [1, 0, 1, 1, 0, 0, 1, 1]
_BITS = len(_SYNC) + 64 + 8      # sync, mark, checksum
_DELTA = 7
_STRIP_H = 6


def _payload(mark: str) -> list[int]:
    raw = bytes.fromhex(mark)
    check = 0
    for b in raw:
        check ^= b
    bits = []
    for b in raw + bytes([check]):
        bits.extend((b >> (7 - i)) & 1 for i in range(8))
    return _SYNC + bits


def _block_width(w: int) -> int:
    return (w - 16) // _BITS


def draw_band_mark(band, mark: Optional[str]) -> None:
    """Darken blocks for 1-bits along the bottom of the (RGBA) footer band, in place."""
    if not mark:
        return
    bw = _block_width(band.width)
    if bw < 2:
        return
    px = band.load()
    y0 = band.height - _STRIP_H - 1
    for i, bit in enumerate(_payload(mark)):
        if not bit:
            continue
        for x in range(8 + i * bw, 8 + (i + 1) * bw):
            for y in range(y0, y0 + _STRIP_H):
                r, g, b, a = px[x, y]
                px[x, y] = (max(0, r - _DELTA), max(0, g - _DELTA), max(0, b - _DELTA), a)


def _read_band_mark(data: bytes) -> Optional[str]:
    from PIL import Image
    img = Image.open(io.BytesIO(data)).convert("L")
    w, h = img.size
    bw = _block_width(w)
    if bw < 2 or h < _STRIP_H + 2:
        return None
    y0 = h - _STRIP_H - 1
    px = img.load()
    means = []
    for i in range(_BITS):
        xs = range(8 + i * bw + (1 if bw > 3 else 0), 8 + (i + 1) * bw - (1 if bw > 3 else 0))
        vals = [px[x, y] for x in xs for y in range(y0 + 1, y0 + _STRIP_H - 1)]
        means.append(sum(vals) / len(vals))
    hi, lo = max(means), min(means)
    if hi - lo < _DELTA / 2:
        return None
    bits = [1 if m < (hi + lo) / 2 else 0 for m in means]
    if bits[:len(_SYNC)] != _SYNC:
        return None
    data_bits = bits[len(_SYNC):]
    raw = bytes(int("".join(map(str, data_bits[i:i + 8])), 2) for i in range(0, len(data_bits), 8))
    check = 0
    for b in raw[:8]:
        check ^= b
    return raw[:8].hex() if check == raw[8] else None


# ------------------------------------------------------------------ Office (OOXML) packages

_PROP = "_LxRef"
_CUSTOM = "docProps/custom.xml"
_CT_CUSTOM = "application/vnd.openxmlformats-officedocument.custom-properties+xml"
_REL_CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties"
_NS_CP = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
_NS_VT = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
_FMTID = "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}"


def embed_ooxml(data: bytes, mark: Optional[str], manifest: Optional[dict] = None) -> bytes:
    """Add the mark as a hidden custom property (Office hides names starting with "_")."""
    if not mark:
        return data
    from lxml import etree
    zin = open_safe_zip(io.BytesIO(data))
    parts = {n: zin.read(n) for n in zin.namelist()}
    created = _CUSTOM not in parts
    if created:
        root = etree.Element(f"{{{_NS_CP}}}Properties", nsmap={None: _NS_CP, "vt": _NS_VT})
        ct = safe_xml_fromstring(parts["[Content_Types].xml"])
        ns = ct.nsmap[None]
        etree.SubElement(ct, f"{{{ns}}}Override", PartName="/" + _CUSTOM, ContentType=_CT_CUSTOM)
        parts["[Content_Types].xml"] = etree.tostring(ct, xml_declaration=True, encoding="UTF-8", standalone=True)
        rels = safe_xml_fromstring(parts["_rels/.rels"])
        rns = rels.nsmap[None]
        used = {r.get("Id") for r in rels}
        rid = next(f"rIdLx{n}" for n in range(1, 1000) if f"rIdLx{n}" not in used)
        etree.SubElement(rels, f"{{{rns}}}Relationship", Id=rid, Type=_REL_CUSTOM, Target=_CUSTOM)
        parts["_rels/.rels"] = etree.tostring(rels, xml_declaration=True, encoding="UTF-8", standalone=True)
    else:
        root = safe_xml_fromstring(parts[_CUSTOM])
    pids = [int(p.get("pid")) for p in root if (p.get("pid") or "").isdigit()]
    prop = etree.SubElement(root, f"{{{_NS_CP}}}property", fmtid=_FMTID, pid=str(max(pids + [1]) + 1), name=_PROP)
    etree.SubElement(prop, f"{{{_NS_VT}}}lpwstr").text = mark
    parts[_CUSTOM] = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
    if manifest is not None:
        manifest["mark_part_created"] = created
    return _zip(zin.namelist() + ([_CUSTOM] if created else []), parts)


def remove_ooxml(data: bytes, manifest: dict) -> bytes:
    """Take the hidden property out again (and the part, if the copy added it)."""
    from lxml import etree
    try:
        zin = open_safe_zip(io.BytesIO(data))
    except (zipfile.BadZipFile, UnsafeFile):
        return data
    names = zin.namelist()
    if _CUSTOM not in names:
        return data
    parts = {n: zin.read(n) for n in names}
    root = safe_xml_fromstring(parts[_CUSTOM])
    for p in [p for p in root if p.get("name") == _PROP]:
        root.remove(p)
    if manifest.get("mark_part_created") and len(root) == 0:
        names = [n for n in names if n != _CUSTOM]
        ct = safe_xml_fromstring(parts["[Content_Types].xml"])
        for o in [o for o in ct if o.get("PartName") == "/" + _CUSTOM]:
            ct.remove(o)
        parts["[Content_Types].xml"] = etree.tostring(ct, xml_declaration=True, encoding="UTF-8", standalone=True)
        rels = safe_xml_fromstring(parts["_rels/.rels"])
        for r in [r for r in rels if r.get("Type") == _REL_CUSTOM and r.get("Target", "").lstrip("/") == _CUSTOM]:
            rels.remove(r)
        parts["_rels/.rels"] = etree.tostring(rels, xml_declaration=True, encoding="UTF-8", standalone=True)
    else:
        parts[_CUSTOM] = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
    return _zip(names, parts)


def _zip(names: list[str], parts: dict) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for n in ["[Content_Types].xml"] + [x for x in names if x != "[Content_Types].xml"]:
            z.writestr(n, parts[n])
    return out.getvalue()


def _read_ooxml_marks(data: bytes) -> list[str]:
    from lxml import etree
    with open_safe_zip(io.BytesIO(data)) as z:
        if _CUSTOM not in z.namelist():
            return []
        root = safe_xml_fromstring(z.read(_CUSTOM))
    return [(p.findtext(f"{{{_NS_VT}}}lpwstr") or "").strip() for p in root if p.get("name") == _PROP]


# ------------------------------------------------------------------ PDF

_PDF_TJ = re.compile(rb"\(([0-9a-f]{16})\)\s*Tj")


def _pdf_forms(resources, depth: int = 0):
    """Form XObjects reachable from a resource dictionary (nested forms included)."""
    if resources is None or depth > 4:
        return
    xobjects = resources.get_object().get("/XObject")
    for ref in (xobjects.get_object().values() if xobjects is not None else []):
        form = ref.get_object()
        if form.get("/Subtype") == "/Form":
            yield form
            yield from _pdf_forms(form.get("/Resources"), depth + 1)


def _read_pdf_marks(data: bytes) -> list[str]:
    from pypdf import PdfReader
    found = []
    for page in limited_pages(PdfReader(io.BytesIO(data)).pages):
        contents = page.get_contents()
        streams = [contents.get_data()] if contents is not None else []
        streams += [form.get_data() for form in _pdf_forms(page.get("/Resources"))]
        for s in streams:
            found.extend(m.decode() for m in _PDF_TJ.findall(s))
    return found


# ------------------------------------------------------------------ reading

def read_marks(data: bytes) -> list[str]:
    """Every mark found in a copy, in order of appearance, without duplicates. Never raises."""
    try:
        if data[:5] == b"%PDF-":
            marks = _read_pdf_marks(data)
        elif data[:4] == b"PK\x03\x04":
            marks = _read_ooxml_marks(data)
        elif data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff":
            m = _read_band_mark(data)
            marks = [m] if m else []
        else:
            marks = []
    except Exception:
        return []
    out = []
    for m in marks:
        if _HEX16.match(m or "") and m not in out:
            out.append(m)
    return out
