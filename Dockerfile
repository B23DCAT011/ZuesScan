# syntax=docker/dockerfile:1
# ZuesScan: the CLI, worker, scheduler and web API in one image, with nmap, nuclei,
# nuclei-templates and subfinder.
#
#   docker build -t zues .
#   docker compose up -d          (see compose.yaml and README: "Docker")
#
# Supply chain: the base image is pinned by digest, every Python package by version AND
# hash (docker/*.lock, regenerated with docker/lock.sh), nmap comes from Debian's signed
# repository, nuclei / subfinder / templates are release files pinned by SHA-256
# (zues_scan/data/tools.lock, the same file `zues tools install` uses; regenerated with
# python -m zues_scan.tools update). Nothing else is fetched.
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# --- build ZuesScan's wheel (pure Python) ----------------------------------------------------
FROM ${PYTHON_IMAGE} AS build
WORKDIR /src
COPY docker/build.lock docker/build.lock
RUN pip install --no-cache-dir --root-user-action=ignore --require-hashes -r docker/build.lock
COPY pyproject.toml README.md ./
COPY zues_scan ./zues_scan
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /wheels .

# --- nuclei, subfinder, nuclei-templates: release files, checked against the lock -----------
FROM ${PYTHON_IMAGE} AS tools
ARG TARGETARCH
# Run as a plain script: zues_scan/tools.py needs only the standard library.
COPY zues_scan/tools.py zues_scan/data/tools.lock /src/
RUN python /src/tools.py install --lock /src/tools.lock --bin /out/bin \
      --templates /out/nuclei-templates --platform "linux-${TARGETARCH:-amd64}"

# --- the image ----------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="ZuesScan" \
      org.opencontainers.image.description="Recon orchestrator and vulnerability management" \
      org.opencontainers.image.source="https://github.com/B23DCAT011/reconkit" \
      org.opencontainers.image.licenses="MIT"

# The SSH client is for authenticated scans (--credentials: installed packages vs the
# Debian tracker); `zues doctor` found it missing from the image.
# nmap, allowed to open raw sockets without being root (SYN scan, traceroute): the one
# capability NET_RAW, which Docker grants by default. A container started with
# --cap-drop ALL (web, scheduler in compose.yaml) cannot run nmap at all; the worker
# adds NET_RAW back.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap openssh-client libcap2-bin \
 && setcap cap_net_raw+eip /usr/bin/nmap \
 && apt-get purge -y libcap2-bin \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY docker/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --root-user-action=ignore --require-hashes -r /tmp/requirements.lock \
 && rm /tmp/requirements.lock
# Templates are data: owned by root, read-only for the scanning user. Signed ones only
# run (nuclei -dut), so a changed template would not run even if it got there.
COPY --from=tools /out/bin/ /usr/local/bin/
COPY --from=tools /out/nuclei-templates /opt/nuclei-templates
COPY --from=build /wheels /tmp/wheels
RUN pip install --no-cache-dir --root-user-action=ignore --no-deps /tmp/wheels/*.whl \
 && rm -rf /tmp/wheels

# Never root: a dedicated user owns the data volume and nothing else.
RUN useradd --uid 10001 --user-group --no-create-home --home-dir /data --shell /usr/sbin/nologin zues \
 && mkdir -p /data /config \
 && chown zues:zues /data

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    NMAP_PRIVILEGED=1 \
    ZUES_NUCLEI_TEMPLATES=/opt/nuclei-templates
USER zues
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000
ENTRYPOINT ["zues"]
CMD ["--help"]
