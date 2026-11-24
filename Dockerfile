# syntax=docker/dockerfile:1.7
# =============================================================================
# Ronny WebScanner - based on KP WebScanner (Kevin Pirnie, MIT)
# Original: https://github.com/kpirnie/webscanner
# Version: 1.1.0-dev
# Build: DOCKER_BUILDKIT=1 docker build --progress=plain -t ronny-webscanner:1.1.0-dev .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Compile Go scanners
# -----------------------------------------------------------------------------
FROM golang:1.27.4-trixie AS go-builder

ENV GOPATH=/go \
    GOBIN=/go/bin \
    GOTOOLCHAIN=local \
    GOPROXY=https://proxy.golang.org|direct \
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git gcc libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# BuildKit caches persist between builds; separate layers protect successful steps.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    for attempt in 1 2 3; do \
      if go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1; then exit 0; fi; \
      echo "Nuclei installation failed (attempt ${attempt}/3)" >&2; \
      sleep 10; \
    done; \
    exit 1

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/OJ/gobuster/v3@latest \
    && go install github.com/hahwul/dalfox/v2@latest

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1

# -----------------------------------------------------------------------------
# Stage 2: Runtime image (same Debian generation as builder for CGO/glibc)
# -----------------------------------------------------------------------------
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    ZAP_DIR=/opt/zap \
    JAVA_OPTS=-Xmx512m \
    WPSCAN_API_TOKEN= \
    SHODAN_API_KEY= \
    CENSYS_APP_ID= \
    CENSYS_TOKEN= \
    PATH=/opt/scanner-venv/bin:/opt/zap:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git bash jq \
      dnsutils iputils-ping net-tools libpcap-dev procps nmap \
      openssl bsdextrautils \
      ruby ruby-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev \
      build-essential libcurl4-openssl-dev libgmp-dev \
      perl libnet-ssleay-perl libio-socket-ssl-perl liburi-perl libwww-perl \
      libjson-perl libxml-writer-perl \
      python3 python3-pip python3-venv \
      dirb default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Dictionaries: fail if download fails rather than silently create an empty list.
RUN mkdir -p /usr/share/wordlists \
    && curl -fSL --retry 3 --retry-all-errors \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt \
       -o /usr/share/wordlists/big.txt \
    && test -s /usr/share/wordlists/big.txt

# Node.js (NodeSource LTS)
RUN curl -fsSL --retry 3 --retry-all-errors \
      https://deb.nodesource.com/setup_lts.x -o /tmp/nodesource_setup.sh \
    && bash /tmp/nodesource_setup.sh \
    && rm /tmp/nodesource_setup.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Python applications in a dedicated virtual environment.
RUN python3 -m venv /opt/scanner-venv \
    && /opt/scanner-venv/bin/pip install --no-cache-dir arjun shodan censys wafw00f

# WhatWeb
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && chmod +x /opt/whatweb/whatweb \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

# WPScan. Vulnerability database updates need a runtime API token.
RUN gem install wpscan --no-document

# sqlmap: always invoke the script via python3 (not /usr/bin/env python).
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# Mozilla HTTP Observatory
RUN npm install -g @mdn/mdn-http-observatory

# Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# testssl.sh
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# OWASP ZAP: resolve the latest release and fail clearly on download errors.
RUN set -eu; \
    ZAP_VERSION="$(curl -fsSL --retry 3 --retry-all-errors \
      https://api.github.com/repos/zaproxy/zaproxy/releases/latest | jq -r '.tag_name | ltrimstr("v")')"; \
    test -n "$ZAP_VERSION" && test "$ZAP_VERSION" != null; \
    wget -q --tries=3 \
      "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
      -O /tmp/zap.tar.gz; \
    mkdir -p "$ZAP_DIR"; \
    tar -xzf /tmp/zap.tar.gz -C "$ZAP_DIR" --strip-components=1; \
    rm /tmp/zap.tar.gz; \
    mkdir -p /root/.ZAP/session /root/.ZAP/dirbuster /root/.ZAP/fuzzers /root/.ZAP/plugin

# Compiled Go scanners
COPY --from=go-builder /go/bin/httpx       /usr/local/bin/httpx
COPY --from=go-builder /go/bin/subfinder   /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/naabu       /usr/local/bin/naabu
COPY --from=go-builder /go/bin/nuclei      /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/katana      /usr/local/bin/katana
COPY --from=go-builder /go/bin/dnsx        /usr/local/bin/dnsx
COPY --from=go-builder /go/bin/ffuf        /usr/local/bin/ffuf
COPY --from=go-builder /go/bin/gobuster    /usr/local/bin/gobuster
COPY --from=go-builder /go/bin/dalfox      /usr/local/bin/dalfox
COPY --from=go-builder /go/bin/osv-scanner /usr/local/bin/osv-scanner

# Fetch templates at build time; missing templates should fail the image build.
RUN nuclei -update-templates -silent \
    && test -d /root/nuclei-templates

# Offline report generator
COPY reporting/ /usr/local/lib/ronny-webscanner/reporting/

# Scanner entrypoint
COPY scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh \
    && /usr/local/bin/sqlmap --version \
    && python3 --version \
    && node --version \
    && test -x /usr/local/bin/nuclei

VOLUME ["/output"]
WORKDIR /output
ENTRYPOINT ["/usr/local/bin/scan.sh"]
CMD ["--help"]
