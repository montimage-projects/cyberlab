# syntax=docker/dockerfile:1.7
#
# cyberlab workbench: one Linux image with everything the MMT generator skills need,
# so nothing MMT-related is built or run on the host (MMT does not build on macOS).
#
#   mmt-dpi        /opt/mmt/dpi, /opt/mmt/plugins   released .deb, sha256 chain-checked
#   mmt-security   /opt/mmt/security (installed), /usr/src/mmt-security (built tree, read-only reference)
#   mmt-plugin     /usr/local/bin/mmt-plugin (venv /opt/mmt-plugin), SDK prefix /sdk/mmt
#   tools          gcc, clang, make, libpcap-dev, libxml2-dev, xmllint, python3 + scapy,
#                  tshark/capinfos/editcap/mergecap, tcpdump, valgrind, jq, git
#
# Built by `scripts/cyberlab build`. Every version is a build argument; the defaults are the
# versions this skill was validated with (see references/environment.md).
ARG UBUNTU=ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5
FROM ${UBUNTU}

ARG DEBIAN_FRONTEND=noninteractive
ARG MMT_DPI_TAG=v1.10.2
ARG MMT_DPI_SUMS_SHA256=
ARG MMT_SECURITY_REPO=https://github.com/Montimage/mmt-security
ARG MMT_SECURITY_REF=a78a4fd4a33a3c4e218c1c4c11e7e1e23b6c7dff
ARG MMT_PLUGIN_REPO=https://github.com/montimage/mmt-plugin-generator
ARG MMT_PLUGIN_REF=7ec9cd99c6a613ed4437926c2e1414f39da4afe7

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git jq make gcc g++ clang libc6-dev dpkg-dev \
        libpcap-dev libxml2-dev libxml2-utils libconfuse-dev \
        python3 python3-venv python3-pip python3-scapy \
        tshark tcpdump valgrind iproute2 \
    && rm -rf /var/lib/apt/lists/*

# mmt-dpi from its GitHub Release (SHA256SUMS pinned, package checked against it).
COPY fetch_mmt_dpi.sh /tmp/fetch_mmt_dpi.sh
RUN deb="$(MMT_DPI_TAG="$MMT_DPI_TAG" MMT_DPI_SUMS_SHA256="$MMT_DPI_SUMS_SHA256" bash /tmp/fetch_mmt_dpi.sh /tmp/mmt-dpi)" \
    && apt-get update && apt-get install -y --no-install-recommends "$deb" \
    && rm -rf /var/lib/apt/lists/* /tmp/mmt-dpi /tmp/fetch_mmt_dpi.sh \
    && test -f /opt/mmt/dpi/include/mmt_log.h && test -f /opt/mmt/plugins/libmmt_tcpip.so

# Private SDK prefix for mmt-plugin (its skill never writes under /opt/mmt). Copied before
# mmt-security is installed, so it holds mmt-dpi only. Absolute .so symlinks become relative.
RUN mkdir -p /sdk/mmt && cp -a /opt/mmt/dpi /opt/mmt/plugins /sdk/mmt/ \
    && for l in /sdk/mmt/dpi/lib/*.so*; do \
         [ -L "$l" ] && ln -sfn "$(basename "$(readlink "$l")")" "$l"; done; \
    test -e /sdk/mmt/dpi/lib/libmmt_core.so

# mmt-security from a pinned commit. Serial make: its `lib` target breaks under -j.
RUN git clone --quiet "$MMT_SECURITY_REPO" /usr/src/mmt-security \
    && cd /usr/src/mmt-security && git checkout --quiet "$MMT_SECURITY_REF" \
    && make && make sample_rules && make install \
    && test -x /usr/src/mmt-security/compile_rule && test -x /usr/src/mmt-security/mmt_sec_standalone \
    && chmod -R a+rX /usr/src/mmt-security /opt/mmt

# mmt-plugin CLI from a pinned commit, in its own venv.
RUN python3 -m venv /opt/mmt-plugin \
    && /opt/mmt-plugin/bin/pip install --no-cache-dir --quiet "git+${MMT_PLUGIN_REPO}@${MMT_PLUGIN_REF}" \
    && ln -s /opt/mmt-plugin/bin/mmt-plugin /usr/local/bin/mmt-plugin \
    && mmt-plugin --json --version >/dev/null

RUN ldconfig && mkdir -p /usr/share/doc/cyberlab \
    && { echo "mmt-dpi $(dpkg-query -W -f='${Version}' mmt-dpi)"; \
         echo "mmt-security $(git -C /usr/src/mmt-security rev-parse --short HEAD)"; \
         echo "mmt-plugin $MMT_PLUGIN_REF"; \
         echo "tshark $(tshark --version | head -1)"; \
         echo "arch $(dpkg --print-architecture)"; } > /usr/share/doc/cyberlab/versions.txt \
    && cat /usr/share/doc/cyberlab/versions.txt

ENV MMT_BASE=/opt/mmt \
    MMT_DPI_DIR=/opt/mmt/dpi \
    MMT_SEC_DIR=/opt/mmt/security \
    CYBERLAB_SDK=/sdk/mmt \
    LD_LIBRARY_PATH=/opt/mmt/dpi/lib:/opt/mmt/security/lib \
    PATH=/opt/mmt/security/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/tmp

LABEL org.cyberlab.role="workbench" \
      org.opencontainers.image.title="cyberlab-workbench" \
      org.opencontainers.image.description="mmt-dpi, mmt-security, mmt-plugin and packet tools for the cyberlab skill"

WORKDIR /work
CMD ["/bin/bash"]
