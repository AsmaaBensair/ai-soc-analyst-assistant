# ── SOC AI Analyst Platform — base image ──────────────────────────────────
# Build once, reused by all services (pipeline, evaluator, dashboard).
# Dependencies installed at build time → no pip install at container start.

FROM python:3.11-slim

WORKDIR /app

# Install system deps (curl for healthchecks, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY requirements.txt .

# Install Python deps once — cached unless requirements.txt changes
RUN pip install --no-cache-dir --disable-pip-version-check --default-timeout=1000 -r requirements.txt

# Copy application code
COPY . .

# Ensure data directory exists in image
RUN mkdir -p data