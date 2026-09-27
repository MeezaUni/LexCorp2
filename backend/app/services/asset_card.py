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
    values = (serial_number, f"#{token_id}", creation_date, department or "-")
    rows = []
    for i, (label, value) in enumerate(zip(CARD_FIELDS, values)):
        y = 124 + i * 58
        rows.append(
            f'<text x="32" y="{y}" font-size="12" fill="#52627a">{escape(label)}</text>'
            f'<text x="32" y="{y + 24}" font-size="19" font-weight="600" fill="#0e2240" '
            f'font-family="IBM Plex Mono, Consolas, Courier New, monospace">{escape(str(value))}</text>'
            f'<line x1="32" y1="{y + 36}" x2="370" y2="{y + 36}" stroke="#d6dde6" stroke-width="1"/>'
        )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 380" width="640" height="380" font-family="IBM Plex Sans, Segoe UI, Arial, sans-serif">
  <rect x="1" y="1" width="638" height="378" rx="6" fill="#ffffff" stroke="#0e2240" stroke-width="2"/>
  <path d="M1 7a6 6 0 0 1 6-6h626a6 6 0 0 1 6 6v65H1z" fill="#0e2240"/>
  <rect x="1" y="72" width="638" height="4" fill="#1f5fbf"/>
  <g transform="translate(28 20)">
    <rect x="1" y="1" width="30" height="30" rx="3" fill="none" stroke="#fff" stroke-width="2"/>
    <rect x="7" y="7" width="5" height="18" fill="#fff"/><rect x="7" y="20" width="18" height="5" fill="#fff"/><rect x="17" y="7" width="8" height="8" fill="#1f5fbf"/>
  </g>
  <text x="72" y="42" font-size="21" font-weight="600" fill="#ffffff">LexCorp registered asset</text>
  <text x="72" y="60" font-size="11" fill="#aebcd0">Asset Assurance &amp; Custody</text>
  {''.join(rows)}
  <rect x="404" y="98" width="208" height="208" fill="#ffffff" stroke="#d6dde6"/>
  <image x="408" y="102" width="200" height="200" href="data:image/png;base64,{qr_b64}"/>
  <text x="508" y="330" font-size="12" fill="#52627a" text-anchor="middle">Scan to verify this asset</text>
</svg>"""
