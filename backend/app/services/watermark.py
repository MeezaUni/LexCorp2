"""Service for dynamic document watermarking."""

import logging
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import io

logger = logging.getLogger(__name__)

async def apply_watermark(file_bytes: bytes, user_did: str, department: str) -> bytes:
    """Apply a dynamic watermark to the document."""
    # For now, implemented for images as Proof-of-Concept.
    # PDF implementation would require pypdf / reportlab.

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    watermark_text = f"USER: {user_did} | DEPT: {department} | TIME: {timestamp}"

    try:
        # Try processing as an image
        image = Image.open(io.BytesIO(file_bytes))
        draw = ImageDraw.Draw(image)
        # Using default font for PoC.
        # In production use a robust font path.
        draw.text((10, 10), watermark_text, fill=(255, 0, 0, 128))

        output = io.BytesIO()
        image.save(output, format=image.format or "PNG")
        return output.getvalue()

    except Exception as e:
        logger.warning(f"Could not apply watermark to file (likely not an image): {e}")
        # Return original if watermarking fails for now, or raise error?
        # For now, return original to avoid blocking access to documents.
        return file_bytes
