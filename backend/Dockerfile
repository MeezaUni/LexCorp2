FROM python:3.11-slim

# Unprivileged runtime user; secrets come from the environment / a secret manager,
# never from the image (see .dockerignore).
RUN useradd --create-home --uid 10001 lexcorp
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=lexcorp:lexcorp . .
USER lexcorp
ENV ENVIRONMENT=production
# Run behind a TLS-terminating reverse proxy listed in TRUSTED_PROXIES (the app reads X-Forwarded-For only from those).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
