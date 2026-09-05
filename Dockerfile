####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.25-bookworm AS go_builder

# Local ES 8 port of malice-plugins/pkgs. Passed as an additional build
# context: docker build --build-context pkgs=../malice-plugins
COPY --from=pkgs . /build/malice-plugins/
COPY . /build/pescan/
WORKDIR /build/pescan

# Pure Go wrapper (shells out to the Python analysis script) -> static binary
# so it runs on the glibc-based runtime below.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/pescan .

####################################################
# PESCAN RUNTIME
####################################################
FROM python:3.12-slim

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/pescan.git"
LABEL malice.plugin.category="exe"
LABEL malice.plugin.mime="application/x-dosexec"
LABEL malice.plugin.docker.engine="*"

# libmagic (the `file` package) backs python-magic for resource file-type
# detection, matching the classic engine's python-magic usage.
RUN apt-get update \
  && apt-get install -y --no-install-recommends file ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Pin the analysis dependencies. pefile is pinned to 2024.8.26 (the classic
# engine used a dead 2018 erocarrera fork); asn1crypto replaces the dead
# signify/pycrypto Authenticode stack; jinja2 renders the markdown;
# python-magic wraps libmagic.
RUN pip install --no-cache-dir \
  "pefile==2024.8.26" \
  "asn1crypto==1.5.1" \
  "Jinja2==3.1.6" \
  "python-magic==0.4.27"

# The Python analysis script, PEiD signature DB, LCID data, and markdown
# template live in /app (read-only, world-readable).
COPY pescan.py pe_analyzer.py signature.py pehash.py lcid.py utils.py markdown.jinja2 /app/
COPY peid/ /app/peid/

COPY --from=go_builder /bin/pescan /bin/pescan

# /malware is the read-only sample mount point (malice volume -> /malware:ro).
# Run as an unprivileged user: the engine only reads the sample and writes to
# Elasticsearch over the network.
RUN useradd -r -u 1000 -m malice \
  && mkdir -p /malware \
  && chown malice:malice /malware

USER malice
WORKDIR /malware

ENTRYPOINT ["pescan"]
CMD ["--help"]

####################################################
####################################################
