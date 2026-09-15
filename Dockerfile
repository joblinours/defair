FROM python:3.13-slim

LABEL maintainer="joblinours"
LABEL description="DEFAIR — Digital Forensics & Incident Response platform"

# Prevent Python from writing .pyc and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# -----------------------------------------------------------------------
# System dependencies for EZ Tools (.NET) and forensic tools
# -----------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    curl \
    libicu-dev \
    sqlite3 \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------
# Install .NET 9.0 runtime (required for EZ Tools net9 builds)
# -----------------------------------------------------------------------
RUN wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm /tmp/dotnet-install.sh

ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="${PATH}:/usr/share/dotnet"

# -----------------------------------------------------------------------
# Install EZ Tools (Eric Zimmerman's forensic tools)
# Uses the official net9 builds from ericzimmermanstools.com
# -----------------------------------------------------------------------
ENV EZTOOLS_DIR=/opt/eztools
RUN mkdir -p ${EZTOOLS_DIR}

# Download EZ Tools — net9 portable versions
RUN cd /tmp && \
    TOOLS="MFTECmd EvtxECmd RECmd PECmd AmcacheParser AppCompatCacheParser LECmd JLECmd RBCmd SBECmd WxTCmd SQLECmd SrumECmd" && \
    for tool in $TOOLS; do \
        echo "Downloading ${tool}..." && \
        wget -q "https://download.ericzimmermanstools.com/net9/${tool}.zip" -O "${tool}.zip" && \
        mkdir -p "${EZTOOLS_DIR}/${tool}" && \
        unzip -q -o "${tool}.zip" -d "${EZTOOLS_DIR}/${tool}" && \
        rm "${tool}.zip"; \
    done

# Create wrapper scripts so tools are on PATH
# Zips may nest with different casing (e.g. EvtxECmd/EvtxeCmd/) so we
# search recursively and case-insensitively for the executable or DLL.
RUN for tool_dir in ${EZTOOLS_DIR}/*/; do \
        tool_name=$(basename "$tool_dir"); \
        # 1) Try native Linux executable (exact name, no extension)
        exe=$(find "$tool_dir" -name "${tool_name}" -type f -executable 2>/dev/null | head -1); \
        if [ -n "$exe" ]; then \
            ln -sf "$exe" "/usr/local/bin/${tool_name}"; \
            echo "  ✓ ${tool_name} → native ($exe)"; \
        else \
            # 2) Try .NET DLL (case-insensitive search for nested dirs)
            dll=$(find "$tool_dir" -iname "${tool_name}.dll" -type f 2>/dev/null | head -1); \
            if [ -n "$dll" ]; then \
                printf '#!/bin/sh\nexec dotnet "%s" "$@"\n' "$dll" > "/usr/local/bin/${tool_name}" && \
                chmod +x "/usr/local/bin/${tool_name}"; \
                echo "  ✓ ${tool_name} → dotnet ($dll)"; \
            else \
                echo "  ✗ ${tool_name} — no executable or DLL found"; \
            fi; \
        fi; \
    done

# -----------------------------------------------------------------------
# Install Hayabusa (Sigma-based EVTX threat hunting)
# -----------------------------------------------------------------------
ARG HAYABUSA_VERSION=4.1.0
RUN cd /tmp && \
    wget -q "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" \
        -O hayabusa.zip && \
    unzip -q hayabusa.zip -d hayabusa && \
    # Binary name matches the zip asset name (no .exe on Linux)
    cp hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu /usr/local/bin/hayabusa && \
    chmod +x /usr/local/bin/hayabusa && \
    # Copy bundled Sigma rules + config
    mkdir -p /opt/hayabusa && \
    cp -r hayabusa/rules /opt/hayabusa/ && \
    cp -r hayabusa/config /opt/hayabusa/ && \
    rm -rf hayabusa hayabusa.zip && \
    echo "  ✓ Hayabusa ${HAYABUSA_VERSION} installed"

# -----------------------------------------------------------------------
# Install YARA + community rules
# -----------------------------------------------------------------------
RUN pip install --no-cache-dir yara-python && \
    mkdir -p /opt/yara/rules && \
    cd /tmp && \
    wget -q "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip" \
        -O yara-rules.zip && \
    unzip -q yara-rules.zip -d yara-rules && \
    cp -r yara-rules/rules-master/* /opt/yara/rules/ && \
    rm -rf yara-rules yara-rules.zip && \
    echo "  ✓ YARA + community rules installed"

# -----------------------------------------------------------------------
# Install DEFAIR Python package + Dissect
# -----------------------------------------------------------------------
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir ".[forensic]"

# -----------------------------------------------------------------------
# Runtime setup
# -----------------------------------------------------------------------

# Default data directory
RUN mkdir -p /data /evidence /workspace

ENV DEFAIR_DB_PATH=/data/defair.db

# Mark as container
RUN touch /.dockerenv

# Default: show help
CMD ["defair", "--help"]
