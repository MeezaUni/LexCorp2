"""Printable physical asset NFT / QR card.

The card may be photographed by outsiders, so it carries ONLY:
  Serial Number, NFT / Token ID, Creation Date, Department, QR code.
Never: MAC address, Unique Address, Creation ID, wallets/DIDs, hashes, owner or
custodian identity, internal audit details. The QR resolves to the public
verification page, which itself shows only minimal fields unless the scanner is
an authenticated, authorized employee.
"""

import base64
from html import escape

from app.services.qr import generate_qr_for_url

CARD_FIELDS = ("Serial Number", "NFT / Token ID", "Creation Date", "Department")


def generate_physical_card_svg(serial_number: str, token_id: int, creation_date: str, department: str, verify_url: str) -> str:
    qr_b64 = base64.b64encode(generate_qr_for_url(verify_url)).decode("ascii")
    values = (serial_number, f"#{token_id}", creation_date, department or "—")
    rows = []
    for i, (label, value) in enumerate(zip(CARD_FIELDS, values)):
        y = 110 + i * 62
        rows.append(
            f'<text x="36" y="{y}" font-size="11" font-weight="700" letter-spacing="1.2" fill="#64748b">{escape(label.upper())}</text>'
            f'<text x="36" y="{y + 26}" font-size="20" font-weight="800" fill="#0f172a" font-family="Courier New, monospace">{escape(str(value))}</text>'
        )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 380" width="640" height="380" font-family="Segoe UI, Arial, sans-serif">
  <rect x="4" y="4" width="632" height="372" rx="16" fill="#ffffff" stroke="#0f172a" stroke-width="3"/>
  <text x="36" y="56" font-size="20" font-weight="800" fill="#0f172a">LexCorp Registered Asset</text>
  {''.join(rows)}
  <image x="400" y="80" width="210" height="210" href="data:image/png;base64,{qr_b64}"/>
  <text x="505" y="312" font-size="11" fill="#475569" text-anchor="middle">Scan to verify</text>
</svg>"""
