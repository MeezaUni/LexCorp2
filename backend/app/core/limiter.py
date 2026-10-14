"""Rate limiting configuration using SlowAPI."""

from slowapi import Limiter

from app.core.client_ip import get_request_client_ip

# Keyed by the real client address (trusted-proxy aware, the same resolution as sessions and the
# audit trail), so people behind the VPN, Caddy or Vite each get their own bucket.
limiter = Limiter(key_func=get_request_client_ip, default_limits=["200/minute"])
