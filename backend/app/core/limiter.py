"""Rate limiting configuration using SlowAPI."""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Default key is remote IP, limits can be tightened per endpoint
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])
