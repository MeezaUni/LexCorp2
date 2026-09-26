"""Is an uploaded file an untampered LexCorp2 copy of one specific action?

Used when a modification copy comes back as a revision: the file must still carry the
watermark LexCorp2 put on it. Two independent checks:
  * QR: at least one QR code in the file decodes to this action's verification reference;
  * Document Control block: the block for this action is present and every field on it
    (downloaded by, wallet, IP, date, Download ID, owner) equals what LexCorp2 recorded
    when the copy was made.
Works for PDF, Word, PowerPoint and Excel copies. Images carry their details only as
pixels, so for them only the QR check applies. Nothing in the file is trusted beyond
this comparison: history always comes from the database.
"""

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Optional

from app.services.watermark import CONTROL_TITLE

ID_RE = re.compile(r"(?:VW|DL|MOD|CRT|ACR)-\d{8}-\d{4}")
LABELS = ("Viewed by", "Downloaded by", "Wallet", "IP", "Date", "View ID", "Download ID", "Owner")
REQUIRED = ("Downloaded by", "Wallet", "Download ID")


@dataclass
class CopyCheck:
    ok: bool
    reason: str
    qr_found: bool = False
    block_found: bool = False
    mismatches: list = field(default_factory=list)


# ------------------------------------------------------------------ text

def _pdf_text(data: bytes) -> str:
    from pypdf import PdfReader
    return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)


def _docx_text(data: bytes) -> str:
    from docx import Document
    from docx.oxml.ns import qn
    doc = Document(io.BytesIO(data))
    # every body paragraph, including those inside content controls (where LexCorp's block lives)
    return "\n".join("".join(t.text or "" for t in p.iter(qn("w:t"))) for p in doc.element.body.iter(qn("w:p")))


def _pptx_text(data: bytes) -> str:
    from pptx import Presentation
    lines = []
    for slide in Presentation(io.BytesIO(data)).slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                lines.extend(p.text for p in shape.text_frame.paragraphs)
    return "\n".join(lines)


def _xlsx_text(z: zipfile.ZipFile) -> str:
    from lxml import etree
    lines = []
    for name in sorted(n for n in z.namelist() if n.startswith("xl/worksheets/") and n.endswith(".xml")):
        root = etree.fromstring(z.read(name))
        for row in root.iter("{*}row"):
            text = "".join(t.text or "" for t in row.iter("{*}t"))
            if text:
                lines.append(text)
    return "\n".join(lines)


def document_text(data: bytes) -> Optional[str]:
    """Readable text of a copy, or None for images."""
    if data[:5] == b"%PDF-":
        return _pdf_text(data)
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist())
            if "word/document.xml" in names:
                return _docx_text(data)
            if "ppt/presentation.xml" in names:
                return _pptx_text(data)
            if "xl/workbook.xml" in names:
                return _xlsx_text(z)
        return ""
    if data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff":
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def control_blocks(text: str) -> list[dict[str, str]]:
    """Each Document Control block as {label: value} (first occurrence of each label)."""
    blocks = []
    for chunk in text.split(CONTROL_TITLE)[1:]:
        fields = {}
        for line in chunk.splitlines():
            if ": " in line:
                label, value = line.split(": ", 1)
                label = label.strip()
                if label in LABELS and label not in fields:
                    fields[label] = value.strip()
        blocks.append(fields)
    return blocks


# ------------------------------------------------------------------ QR

def _images(data: bytes) -> list[bytes]:
    out = []
    if data[:5] == b"%PDF-":
        from pypdf import PdfReader
        for page in PdfReader(io.BytesIO(data)).pages:
            try:
                out.extend(img.data for img in page.images)
            except Exception:
                continue
    elif data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            out.extend(z.read(n) for n in z.namelist() if "/media/" in n)
    else:
        out.append(data)
    return out


def _decode_qr(image_bytes: bytes) -> list[str]:
    import cv2
    import numpy as np
    img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
    if img is None:
        return []
    found = []
    detector = cv2.QRCodeDetector()
    for scale in (1, 4):
        candidate = img if scale == 1 else cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
        candidate = cv2.copyMakeBorder(candidate, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
        ok, texts, _, _ = detector.detectAndDecodeMulti(candidate)
        if ok:
            found.extend(t for t in texts if t)
        text, _, _ = detector.detectAndDecode(candidate)
        if text:
            found.append(text)
        if found:
            break
    return found


def qr_references(data: bytes) -> set[str]:
    """LexCorp2 action references found in the file's QR codes."""
    refs = set()
    for image in _images(data):
        for payload in _decode_qr(image):
            refs.update(ID_RE.findall(payload))
    return refs


# ------------------------------------------------------------------ check

def recorded_fields(watermark_text: str) -> dict[str, str]:
    out = {}
    for line in (watermark_text or "").splitlines():
        if ": " in line:
            label, value = line.split(": ", 1)
            if label in LABELS and label not in out:
                out[label] = value.strip()
    return out


def check_copy(data: bytes, action_id: str, watermark_text: str) -> CopyCheck:
    refs = qr_references(data)
    if action_id not in refs:
        return CopyCheck(False, f"The file has no QR code for {action_id}: the watermark was removed or the file is not "
                                f"the copy downloaded as {action_id}.")
    text = document_text(data)
    if text is None:
        return CopyCheck(True, "QR code verified (images carry no readable control block).", qr_found=True)
    block = next((b for b in control_blocks(text) if b.get("Download ID") == action_id), None)
    if block is None:
        return CopyCheck(False, f"The LexCorp Document Control block for {action_id} is missing from the file.", qr_found=True)
    recorded = recorded_fields(watermark_text)
    mismatches = [label for label in LABELS if label in block and block[label] != recorded.get(label)]
    mismatches += [label for label in REQUIRED if label not in block]
    if mismatches:
        return CopyCheck(False, "The watermark on the file does not match LexCorp2's record (changed: "
                                + ", ".join(sorted(set(mismatches))) + ").", True, True, sorted(set(mismatches)))
    return CopyCheck(True, "QR code and watermark details match the record.", True, True)
