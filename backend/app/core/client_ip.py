"""The client's IP address, resolved the same way everywhere (sessions, audit, rate limits).

X-Forwarded-For is honoured only when the direct peer is a configured trusted proxy
(settings.TRUSTED_PROXIES); the chain is walked right-to-left, skipping trusted hops, and the
first untrusted address is the client. A client talking to the API directly cannot choose
its own IP by sending the header.
"""

import ipaddress
import logging

from starlette.requests import Request

from app.core.config import settings

logger = logging.getLogger(__name__)


def _trusted_networks():
    nets = []
    for cidr in settings.TRUSTED_PROXIES:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.error("Ignoring invalid TRUSTED_PROXIES entry: %s", cidr)
    return nets


def _normalize_ip(ip: str) -> str:
    ip = (ip or "").strip()
    if ip in ("localhost", "testclient", "::1"):
        return "127.0.0.1"
    if ip.startswith("::ffff:"):
        ip = ip[len("::ffff:"):]
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _is_trusted(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def get_request_client_ip(request: Request) -> str:
    """Effective client IP from the trusted server-side request context.

    X-Forwarded-For is honoured only when the direct peer is a configured trusted
    proxy; the chain is then walked right-to-left, skipping trusted hops, and the
    first untrusted address is the client. A client talking to the API directly
    cannot choose its own IP by sending the header."""
    peer = _normalize_ip(request.client.host if request.client else "127.0.0.1")
    nets = _trusted_networks()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and _is_trusted(peer, nets):
        hops = [_normalize_ip(h) for h in forwarded.split(",") if h.strip()]
        for hop in reversed(hops):
            if not _is_trusted(hop, nets):
                return hop
        if hops:
            return hops[0]
    return peer
