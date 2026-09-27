FROM python:3.11-slim

# Unprivileged runtime user; secrets come from the environment / a secret manager,
# never from the image (see .dockerignore).
RUN useradd --create-home --uid 10001 lexcorp
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=lexcorp:lexcorp . .
# The document vault must be writable by the runtime user; mount a persistent volume here.
RUN mkdir -p /app/offchain_storage && chown lexcorp:lexcorp /app /app/offchain_storage
VOLUME ["/app/offchain_storage"]
USER lexcorp
ENV ENVIRONMENT=production
# The ledger deployment record lives outside backend/ (contracts/deployments/besu.json), so it is not
# in the image: mount it read-only and point CONTRACT_DEPLOYMENT_PATH at it, e.g.
#   -v /path/to/besu.json:/run/lexcorp/besu.json:ro -e CONTRACT_DEPLOYMENT_PATH=/run/lexcorp/besu.json
# Run database migrations (alembic upgrade head) before starting a new version.
# Run behind a TLS-terminating reverse proxy listed in TRUSTED_PROXIES (the app reads X-Forwarded-For only from those).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
