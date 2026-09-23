"""Service for dynamic document watermarking."""

import logging
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import io
from typing import Optional, List

logger = logging.getLogger(__name__)

async def apply_watermark(
    file_bytes: bytes,
    user_did: str,
    department: str,
    token: Optional[str] = None,
    revision_history: Optional[List[str]] = None
) -> bytes:
    """Apply a dynamic watermark to the document (Image or Text)."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"LEXCORP SECURE VAULT - CLASSIFIED",
        f"VIEWER DID: {user_did}",
        f"DEPARTMENT: {department}",
        f"TIMESTAMP : {timestamp}",
    ]
    if token:
        lines.append(f"DL TOKEN  : {token}")
    if revision_history:
        lines.append(f"LINEAGE   : {' -> '.join(revision_history)}")

    watermark_text = " | ".join(lines)

    # 1. Try processing as an image
    try:
        image = Image.open(io.BytesIO(file_bytes))
        draw = ImageDraw.Draw(image)

        y_pos = 10
        for line in lines:
            draw.text((10, y_pos), line, fill=(255, 0, 0, 180))
            y_pos += 18

        output = io.BytesIO()
        image.save(output, format=image.format or "PNG")
        return output.getvalue()
    except Exception:
        pass

    # 2. Try processing as UTF-8 text file
    try:
        text_content = file_bytes.decode("utf-8")
        banner = "\n".join([
            "=" * 70,
            "*** LEXCORP SECURE VAULT - DIGITAL WATERMARK ***",
            *lines,
            "=" * 70,
            ""
        ])
        watermarked_text = banner + "\n" + text_content
        return watermarked_text.encode("utf-8")
    except Exception:
        pass

    # Fallback return original
    return file_bytes
