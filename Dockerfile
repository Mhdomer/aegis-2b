# Multi-stage build for minimal image size and attack surface
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy uv binary for rapid package build
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project specification and source trees
COPY pyproject.toml README.md aegis.yaml ./
COPY aegis/ aegis/
COPY patterns/ patterns/
COPY ui/ ui/

# Build wheel package
RUN uv build --wheel --out-dir dist

# Final hardened production runtime
FROM python:3.12-slim AS runtime

# Security and environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8765

# Create dedicated non-root aegis system user and workspace
RUN groupadd -r aegis && useradd -r -g aegis -u 1000 -d /home/aegis -m -s /bin/bash aegis && \
    mkdir -p /workspace && chown -R aegis:aegis /workspace /home/aegis

WORKDIR /workspace

# Install wheel from builder stage
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm -rf /tmp/*.whl

# Copy default policy specification to workspace
COPY aegis.yaml /workspace/aegis.yaml
RUN chown aegis:aegis /workspace/aegis.yaml

# Switch to non-root user
USER aegis

# Expose Web Operations Center port
EXPOSE 8765

# OCI standard container metadata
LABEL org.opencontainers.image.title="aegis-2b" \
      org.opencontainers.image.description="Sub-Second Safety Circuit Breaker for Autonomous Cloud Ops Agents using Strands Decider 2B" \
      org.opencontainers.image.url="https://github.com/Mhdomer/aegis-2b" \
      org.opencontainers.image.source="https://github.com/Mhdomer/aegis-2b" \
      org.opencontainers.image.vendor="Mohamed Makhlouf" \
      org.opencontainers.image.licenses="MIT"

# Default CLI entrypoint
ENTRYPOINT ["aegis"]

# Default command displays overview / help
CMD ["--help"]
