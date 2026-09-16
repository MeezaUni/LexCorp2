"""Visual Asset Card & Certificate Generator for BEL Defense Assets.

Generates cryptographic, tamper-evident visual asset cards (SVG / HTML / printable format)
embedding the hardware serial, token ID, SHA-256 fingerprint, owner/custodian DIDs,
and live verification QR code for physical-to-digital asset binding.
"""

import base64
from typing import Optional
from app.services.qr import generate_qr_for_url

def generate_asset_certificate_svg(
    serial_number: str,
    token_id: int,
    name: str,
    asset_type: str,
    owner_did: str,
    custodian_did: Optional[str],
    custodian_department: Optional[str],
    file_hash: Optional[str],
    lifecycle_status: str,
    verify_url: str
) -> str:
    """Generate high-resolution printable SVG Defense Asset Certificate."""
    # Generate QR code png bytes and base64 encode it for embedding in SVG
    qr_png = generate_qr_for_url(verify_url)
    qr_b64 = base64.b64encode(qr_png).decode("utf-8")

    short_owner = f"{owner_did[:16]}...{owner_did[-8:]}" if len(owner_did) > 28 else owner_did
    custodian_text = custodian_department or "UNASSIGNED"
    if custodian_did:
        short_cust = f"{custodian_did[:14]}...{custodian_did[-6:]}" if len(custodian_did) > 24 else custodian_did
        custodian_text = f"{custodian_text} ({short_cust})"

    short_hash = f"{file_hash[:20]}...{file_hash[-12:]}" if file_hash and len(file_hash) > 36 else (file_hash or "N/A (PHYSICAL UNIT)")
    asset_name = name or f"BEL Defense Asset {serial_number}"

    # Status color mapping
    status_colors = {
        "CREATED": "#3b82f6",
        "VERIFIED": "#10b981",
        "ASSIGNED": "#06b6d4",
        "MAINTENANCE": "#f59e0b",
        "TRANSFERRED": "#8b5cf6",
        "RETIRED": "#ef4444"
    }
    status_color = status_colors.get(lifecycle_status.upper(), "#10b981")

    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 850 540" width="850" height="540" style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0b132b" />
      <stop offset="50%" stop-color="#1c2541" />
      <stop offset="100%" stop-color="#0b132b" />
    </linearGradient>
    <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#f59e0b" />
      <stop offset="50%" stop-color="#fbbf24" />
      <stop offset="100%" stop-color="#d97706" />
    </linearGradient>
    <linearGradient id="cyanGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#00f2fe" />
      <stop offset="100%" stop-color="#4facfe" />
    </linearGradient>
    <pattern id="securityGrid" width="20" height="20" patternUnits="userSpaceOnUse">
      <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(0, 242, 254, 0.04)" stroke-width="1"/>
    </pattern>
    <filter id="cardShadow" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="12" stdDeviation="16" flood-color="#000" flood-opacity="0.6"/>
    </filter>
  </defs>

  <!-- Card Background -->
  <rect x="15" y="15" width="820" height="510" rx="16" fill="url(#bgGrad)" stroke="#1e293b" stroke-width="2" filter="url(#cardShadow)"/>
  <rect x="15" y="15" width="820" height="510" rx="16" fill="url(#securityGrid)"/>

  <!-- Ornate Border Frame -->
  <rect x="25" y="25" width="800" height="490" rx="12" fill="none" stroke="rgba(251, 191, 36, 0.3)" stroke-width="1.5" stroke-dasharray="8 4"/>
  <rect x="30" y="30" width="790" height="480" rx="10" fill="none" stroke="rgba(0, 242, 254, 0.2)" stroke-width="1"/>

  <!-- Corner Accents -->
  <!-- Top Left -->
  <path d="M 30 50 L 30 30 L 50 30" fill="none" stroke="#00f2fe" stroke-width="3"/>
  <!-- Top Right -->
  <path d="M 800 30 L 820 30 L 820 50" fill="none" stroke="#00f2fe" stroke-width="3"/>
  <!-- Bottom Left -->
  <path d="M 30 490 L 30 510 L 50 510" fill="none" stroke="#00f2fe" stroke-width="3"/>
  <!-- Bottom Right -->
  <path d="M 800 510 L 820 510 L 820 490" fill="none" stroke="#00f2fe" stroke-width="3"/>

  <!-- Header Section -->
  <g transform="translate(50, 50)">
    <!-- Emblem Circle -->
    <circle cx="28" cy="28" r="24" fill="#0f172a" stroke="#fbbf24" stroke-width="2"/>
    <text x="28" y="34" font-size="14" font-weight="900" fill="#fbbf24" text-anchor="middle">BEL</text>

    <!-- Header Text -->
    <text x="68" y="22" font-size="15" font-weight="800" letter-spacing="2" fill="url(#goldGrad)">BHARAT ELECTRONICS LIMITED</text>
    <text x="68" y="42" font-size="11" font-weight="600" letter-spacing="1.5" fill="#94a3b8">DEFENSE CRYPTOGRAPHIC ASSET CERTIFICATE &amp; IDENTITY PASSPORT</text>

    <!-- Classification Badge -->
    <rect x="580" y="10" width="160" height="28" rx="6" fill="rgba(239, 68, 68, 0.15)" stroke="#ef4444" stroke-width="1"/>
    <text x="660" y="28" font-size="10" font-weight="800" letter-spacing="1.5" fill="#f87171" text-anchor="middle">DEFENSE RESTRICTED</text>
  </g>

  <!-- Divider Line -->
  <line x1="50" y1="120" x2="800" y2="120" stroke="rgba(255, 255, 255, 0.1)" stroke-width="1"/>

  <!-- Main Body Content -->
  <!-- Left Column: Asset Details -->
  <g transform="translate(50, 145)">
    <!-- Asset Name & Type -->
    <text x="0" y="0" font-size="11" font-weight="700" letter-spacing="1" fill="#64748b">ASSET NOMENCLATURE / SPECIFICATION</text>
    <text x="0" y="24" font-size="18" font-weight="800" fill="#f8fafc">{asset_name}</text>

    <!-- Serial & Token ID Grid -->
    <g transform="translate(0, 50)">
      <!-- Hardware Serial -->
      <rect x="0" y="0" width="240" height="52" rx="8" fill="rgba(15, 23, 42, 0.6)" stroke="rgba(0, 242, 254, 0.2)" stroke-width="1"/>
      <text x="14" y="18" font-size="9" font-weight="700" letter-spacing="1" fill="#00f2fe">PHYSICAL HARDWARE SERIAL</text>
      <text x="14" y="38" font-size="14" font-weight="800" fill="#ffffff" font-family="'Courier New', monospace">{serial_number}</text>

      <!-- Token ID -->
      <rect x="255" y="0" width="190" height="52" rx="8" fill="rgba(15, 23, 42, 0.6)" stroke="rgba(251, 191, 36, 0.2)" stroke-width="1"/>
      <text x="269" y="18" font-size="9" font-weight="700" letter-spacing="1" fill="#fbbf24">ON-CHAIN TOKEN ID</text>
      <text x="269" y="38" font-size="15" font-weight="800" fill="#fbbf24" font-family="'Courier New', monospace">#{token_id}</text>
    </g>

    <!-- Lifecycle Status & Type -->
    <g transform="translate(0, 120)">
      <text x="0" y="0" font-size="9" font-weight="700" letter-spacing="1" fill="#64748b">LIFECYCLE STATUS</text>
      <rect x="0" y="10" width="130" height="24" rx="4" fill="{status_color}22" stroke="{status_color}" stroke-width="1"/>
      <circle cx="12" cy="22" r="4" fill="{status_color}"/>
      <text x="24" y="26" font-size="10" font-weight="800" fill="{status_color}">{lifecycle_status.upper()}</text>

      <text x="150" y="0" font-size="9" font-weight="700" letter-spacing="1" fill="#64748b">ASSET CLASSIFICATION</text>
      <rect x="150" y="10" width="150" height="24" rx="4" fill="rgba(100, 116, 139, 0.2)" stroke="#64748b" stroke-width="1"/>
      <text x="225" y="26" font-size="10" font-weight="700" fill="#cbd5e1" text-anchor="middle">{asset_type.upper()}</text>
    </g>

    <!-- Custody & Governance -->
    <g transform="translate(0, 175)">
      <text x="0" y="0" font-size="9" font-weight="700" letter-spacing="1" fill="#64748b">SOVEREIGN OWNER (W3C DID)</text>
      <text x="0" y="18" font-size="11" font-weight="600" fill="#93c5fd" font-family="'Courier New', monospace">{short_owner}</text>

      <text x="0" y="42" font-size="9" font-weight="700" letter-spacing="1" fill="#64748b">CURRENT CUSTODIAN &amp; DIVISION</text>
      <text x="0" y="60" font-size="11" font-weight="600" fill="#e2e8f0">{custodian_text}</text>
    </g>

    <!-- SHA-256 Fingerprint -->
    <g transform="translate(0, 255)">
      <text x="0" y="0" font-size="9" font-weight="700" letter-spacing="1" fill="#64748b">CRYPTOGRAPHIC SHA-256 FIRMWARE / SPEC HASH</text>
      <rect x="0" y="8" width="445" height="28" rx="4" fill="#0f172a" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
      <text x="10" y="26" font-size="10" font-weight="600" fill="#38bdf8" font-family="'Courier New', monospace">{short_hash}</text>
    </g>
  </g>

  <!-- Right Column: Verification QR Code & Seal -->
  <g transform="translate(545, 145)">
    <!-- QR Box Container -->
    <rect x="0" y="0" width="250" height="285" rx="12" fill="#0f172a" stroke="rgba(0, 242, 254, 0.3)" stroke-width="1.5"/>

    <!-- QR Header -->
    <text x="125" y="26" font-size="10" font-weight="800" letter-spacing="1" fill="#00f2fe" text-anchor="middle">INSTANT ON-CHAIN VERIFICATION</text>

    <!-- Embedded QR Image -->
    <image x="30" y="40" width="190" height="190" href="data:image/png;base64,{qr_b64}"/>

    <!-- Scan Instruction -->
    <text x="125" y="248" font-size="9" font-weight="600" fill="#94a3b8" text-anchor="middle">Scan via Field Terminal / Mobile</text>
    <text x="125" y="264" font-size="8" font-weight="500" fill="#64748b" text-anchor="middle">Cryptographically Verified on Hyperledger Besu</text>
  </g>

  <!-- Footer Security Bar -->
  <g transform="translate(50, 485)">
    <line x1="0" y1="0" x2="750" y2="0" stroke="rgba(255, 255, 255, 0.1)" stroke-width="1"/>
    <text x="0" y="18" font-size="8.5" font-weight="600" fill="#64748b">HYPERLEDGER BESU QBFT CONSORTIUM — CHAIN ID 13371 • SMART INDIA HACKATHON 2026 PS 26125</text>
    <text x="750" y="18" font-size="8.5" font-weight="700" fill="#fbbf24" text-anchor="end">BHARAT ELECTRONICS LIMITED CONFIDENTIAL</text>
  </g>
</svg>
"""
    return svg_content
