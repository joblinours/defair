FROM python:3.13-slim

LABEL maintainer="lucas.joblin@gmail.com"
LABEL description="DEFAIR — Digital Forensics & Incident Response platform"

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install project
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

# Default data directory
RUN mkdir -p /data /evidence

ENV DEFAIR_DB_PATH=/data/defair.db

# Default: show help
CMD ["defair", "--help"]
