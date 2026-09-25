# =============================================================================
# DEFAIR — forensic worker image (built in CI, pulled from GHCR)
# =============================================================================
# Stages:
#   fetch        → pinned downloads, every archive checked against
#                  docker/checksums.sha256 (build fails on any mismatch)
#   raijin-build → Raijin (engines/raijin) compiled from the vendored source
#   wheels       → Python wheels, C extensions compiled here only
#   rules        → `defair rules sync`: YARA / Sigma rule sets pinned in
#                  src/defair/rules/lock, verified file by file, then
#                  validated by raijin-util (build fails on any mismatch)
#   final        → runtime image, no compiler, no download tooling
#
# Bumping a tool: update its ARG / docker/checksums.sha256 in a reviewed commit.
# EZ Tools are served under unversioned URLs: an upstream release changes the
# archive and fails the checksum on purpose until the new hash is pinned.
# =============================================================================

ARG PYTHON_IMAGE=python:3.13-slim

# -----------------------------------------------------------------------------
# Stage 1 — fetch (pinned + checksummed downloads)
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS fetch

ARG HAYABUSA_VERSION=4.1.0
ARG DOTNET_VERSION=9.0.20
ARG DOTNET_SHA512=aaa63e9156fcc9d1c51e15fb38e3c5388a7721ef1b64065c8865b03133906e9de967ae33903c198c6acb9aa8bbae373e9001405074009c2ef2a0bb6e54b509a5

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /dl
COPY docker/checksums.sha256 docker/write_versions.py ./

ENV EZ_TOOLS="MFTECmd EvtxECmd RECmd PECmd AmcacheParser AppCompatCacheParser LECmd JLECmd RBCmd SBECmd WxTCmd SQLECmd SrumECmd RecentFileCacheParser SumECmd bstrings rla"

RUN set -eu; \
    for tool in $EZ_TOOLS; do \
        curl -sfL -A "Mozilla/5.0" -o "${tool}.zip" \
            "https://download.ericzimmermanstools.com/net9/${tool}.zip"; \
    done; \
    curl -sfL -o "hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip"; \
    sha256sum -c checksums.sha256; \
    curl -sfL -o dotnet.tar.gz \
        "https://builds.dotnet.microsoft.com/dotnet/Runtime/${DOTNET_VERSION}/dotnet-runtime-${DOTNET_VERSION}-linux-x64.tar.gz"; \
    echo "${DOTNET_SHA512}  dotnet.tar.gz" | sha512sum -c -

# Unpack into the final layout
RUN set -eu; \
    mkdir -p /out/usr/share/dotnet /out/opt/eztools /out/opt/hayabusa /out/usr/local/bin; \
    tar -xzf dotnet.tar.gz -C /out/usr/share/dotnet; \
    for tool in $EZ_TOOLS; do \
        unzip -q -o "${tool}.zip" -d "/out/opt/eztools/${tool}"; \
    done; \
    unzip -q "hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" -d hayabusa; \
    cp "hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu" /out/usr/local/bin/hayabusa; \
    chmod +x /out/usr/local/bin/hayabusa; \
    cp -r hayabusa/rules hayabusa/config /out/opt/hayabusa/; \
    python3 write_versions.py checksums.sha256 "${HAYABUSA_VERSION}" "${DOTNET_VERSION}"; \
    mkdir -p /out/opt/defair && cp /opt/defair/versions.json /out/opt/defair/

# EZ Tools wrappers: zips may nest with different casing (EvtxECmd/EvtxeCmd/),
# so search recursively and case-insensitively for the executable or DLL.
RUN set -eu; \
    for tool_dir in /out/opt/eztools/*/; do \
        tool_name=$(basename "$tool_dir"); \
        exe=$(find "$tool_dir" -name "${tool_name}" -type f -executable | head -1); \
        if [ -n "$exe" ]; then \
            ln -sf "${exe#/out}" "/out/usr/local/bin/${tool_name}"; \
        else \
            dll=$(find "$tool_dir" -iname "${tool_name}.dll" -type f | head -1); \
            [ -n "$dll" ] || { echo "no executable or DLL for ${tool_name}" >&2; exit 1; }; \
            printf '#!/bin/sh\nexec dotnet "%s" "$@"\n' "${dll#/out}" > "/out/usr/local/bin/${tool_name}"; \
            chmod +x "/out/usr/local/bin/${tool_name}"; \
        fi; \
    done

# -----------------------------------------------------------------------------
# Stage 2 — Raijin (vendored YARA-X + Sigma scanner, pinned Rust toolchain)
# -----------------------------------------------------------------------------
FROM rust:1.91.0-slim-bookworm AS raijin-build

WORKDIR /build
COPY engines/raijin/ ./
RUN cargo build --release --locked \
    && install -m 0755 target/release/raijin target/release/raijin-util /usr/local/bin/

# -----------------------------------------------------------------------------
# Stage 3 — wheels (compilers live here only)
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS wheels

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src/ src/
# ANSSI orc-decrypt (vendored, LGPL-2.1): Python module + compiled `unstream`
COPY engines/orc-decrypt/ engines/orc-decrypt/
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[forensic]" ./engines/orc-decrypt

# -----------------------------------------------------------------------------
# Stage 4 — rules (pinned + verified detection rule sets)
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS rules

COPY --from=wheels /wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index --find-links /tmp/wheels defair
COPY --from=raijin-build /usr/local/bin/raijin-util /usr/local/bin/raijin-util
COPY docker/validate_rules.py /tmp/validate_rules.py
RUN defair rules sync --dest /opt/defair/rules \
    && python3 /tmp/validate_rules.py /opt/defair/rules /usr/local/bin/raijin-util

# -----------------------------------------------------------------------------
# Stage 5 — final runtime image
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS final

LABEL org.opencontainers.image.title="DEFAIR" \
      org.opencontainers.image.description="DEFAIR — Digital Forensics & Incident Response platform" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/joblinours/defair"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOTNET_ROOT=/usr/share/dotnet \
    PATH="${PATH}:/usr/share/dotnet" \
    EZTOOLS_DIR=/opt/eztools \
    DEFAIR_RULES_STORE=/opt/defair/rules \
    DEFAIR_DB_PATH=/data/defair.db

# Runtime libraries only: ICU for .NET globalization, sqlite3 for SBECmd/SQLECmd
RUN apt-get update && apt-get install -y --no-install-recommends \
        libicu-dev sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=fetch /out/ /
RUN ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet
COPY --from=raijin-build /usr/local/bin/raijin /usr/local/bin/raijin-util /usr/local/bin/
COPY engines/raijin/LICENSE engines/raijin/LICENSING.md /usr/share/doc/raijin/
COPY engines/orc-decrypt/LICENSE.txt /usr/share/doc/orc-decrypt/LICENSE.txt
COPY --from=rules /opt/defair/rules /opt/defair/rules

COPY --from=wheels /wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index --find-links /tmp/wheels "defair[forensic]" anssi-orcdecrypt \
    && command -v unstream \
    && rm -rf /tmp/wheels

WORKDIR /app
RUN mkdir -p /data /evidence /workspace /rules /keys \
    && chmod 1777 /data /workspace \
    && touch /.dockerenv

CMD ["defair", "--help"]
