# =============================================================================
# DEFAIR — worker-plaso: Plaso + The Sleuth Kit (supertimeline jobs, v0.5)
# =============================================================================
# Built in CI (matrix of .github/workflows/ci.yml), pulled from GHCR as
# ghcr.io/joblinours/defair-worker-plaso:<version> — never built locally.
#
# Started by the HOST as a short-lived job next to a case container (see
# services/worker_service.py): no network, every capability dropped,
# read-only rootfs, host user. It runs `python -m defair.workers.entry
# /workspace/jobs/<RUN>/job.json` — argv lists written by the case container.
#
# Stages:
#   builder → libewf-legacy + Sleuth Kit compiled from tarballs pinned in
#             docker/worker-plaso.checksums.sha256; Plaso and every Python
#             dependency built from docker/worker-plaso.requirements.txt
#             (pip --require-hashes); the DEFAIR runner as a wheel
#   final   → runtime only, no compiler, no download tooling
#
# Bumping a component: change its ARG / checksum / lock line in a reviewed commit.
# =============================================================================

ARG PYTHON_IMAGE=python:3.13-slim

# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

ARG LIBEWF_VERSION=20140816
ARG TSK_VERSION=4.15.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config curl ca-certificates \
        zlib1g-dev libbz2-dev libssl-dev libfuse3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY docker/worker-plaso.checksums.sha256 docker/worker-plaso.requirements.txt docker/write_versions.py ./

# Pinned + checksummed sources (the build fails on any mismatch)
RUN set -eu; \
    curl -sfL -o "libewf-${LIBEWF_VERSION}.tar.gz" \
        "https://github.com/libyal/libewf-legacy/releases/download/${LIBEWF_VERSION}/libewf-${LIBEWF_VERSION}.tar.gz"; \
    curl -sfL -o "sleuthkit-${TSK_VERSION}.tar.gz" \
        "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-${TSK_VERSION}/sleuthkit-${TSK_VERSION}.tar.gz"; \
    sha256sum -c worker-plaso.checksums.sha256

# libewf-legacy (the API the Sleuth Kit uses) as a static library, then the
# Sleuth Kit linked against it: mmls / fls / blkls read E01 / Ex01 directly
RUN set -eu; \
    tar -xzf "libewf-${LIBEWF_VERSION}.tar.gz"; \
    cd "libewf-${LIBEWF_VERSION}"; \
    ./configure --prefix=/opt/libewf --disable-shared --enable-static --without-libfuse --disable-python --quiet; \
    make -j"$(nproc)" -s; make install -s
RUN set -eu; \
    tar -xzf "sleuthkit-${TSK_VERSION}.tar.gz"; \
    cd "sleuthkit-${TSK_VERSION}"; \
    LIBS="-lbz2 -lz -lcrypto" ./configure --prefix=/opt/tsk --disable-java --without-afflib \
        --without-libvhdi --without-libvmdk --with-libewf=/opt/libewf --disable-shared --enable-static \
        | tee /tmp/tsk-configure.txt; \
    grep -Eq "libewf support: +yes" /tmp/tsk-configure.txt; \
    make -j"$(nproc)" -s; make install -s; \
    mkdir -p /opt/tsk/share/doc && cp -r licenses /opt/tsk/share/doc/sleuthkit; \
    /opt/tsk/bin/fls -V

# Plaso + dependencies: every artifact checked against the lock's SHA-256,
# C extensions (libyal bindings) compiled here only
RUN pip wheel --no-cache-dir --require-hashes -r worker-plaso.requirements.txt --wheel-dir /wheels

# The DEFAIR job runner (standard library only: installed without dependencies)
COPY pyproject.toml README.md /src/
COPY src/ /src/src/
RUN pip wheel --no-cache-dir --no-deps /src --wheel-dir /wheels-defair

RUN set -eu; \
    PLASO_VERSION=$(sed -n 's/^plaso==\([0-9]*\).*/\1/p' worker-plaso.requirements.txt); \
    python3 write_versions.py worker-plaso.checksums.sha256 - - "plaso=${PLASO_VERSION}" \
        "python=$(python3 -c 'import platform; print(platform.python_version())')"

# -----------------------------------------------------------------------------
# Stage 2 — final runtime image
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS final

LABEL org.opencontainers.image.title="DEFAIR worker-plaso" \
      org.opencontainers.image.description="DEFAIR supertimeline worker — Plaso + The Sleuth Kit" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0 AND IPL-1.0 AND CPL-1.0 AND LGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/joblinours/defair"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    DEFAIR_WORKSPACE=/workspace

# Runtime libraries of the Sleuth Kit tools (libewf is linked in statically)
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/tsk/bin/ /usr/local/bin/
COPY --from=builder /opt/tsk/share/doc/sleuthkit/ /usr/share/doc/sleuthkit/
COPY --from=builder /opt/defair/versions.json /opt/defair/versions.json
COPY --from=builder /wheels /tmp/wheels
COPY --from=builder /wheels-defair /tmp/wheels-defair
COPY docker/worker-plaso.requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir --no-index --find-links /tmp/wheels \
        $(sed -n 's/^\([A-Za-z0-9_.-]*==[^ ]*\).*/\1/p' /tmp/requirements.txt) \
    && pip install --no-cache-dir --no-index --no-deps /tmp/wheels-defair/*.whl \
    && rm -rf /tmp/wheels /tmp/wheels-defair /tmp/requirements.txt \
    && python3 -m defair.workers.check

WORKDIR /workspace
CMD ["python3", "-m", "defair.workers.check"]
