# cyberlab tools image: the only image cyberlab itself needs.
#   capture sidecar   tcpdump in the victim's network namespace, writing to /cap inside the
#                     container (fast); `cyberlab run` copies the trace out after stopping it
#   checks            python3 (lab_policy.py, verify.py, craft_pcap.py), tshark/capinfos
# Nothing else: tools a mission's consumer needs (IDS, DPI, parsers) belong in the consumer's
# own environment, not in the lab. Built by `cyberlab build`.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache bash python3 tcpdump tshark \
    && mkdir -p /cap && chmod 1777 /cap \
    && tshark --version | head -1 && tcpdump --version 2>&1 | head -1 && python3 --version
LABEL org.cyberlab.role="tools"
ENV HOME=/tmp
WORKDIR /lab
CMD ["/bin/bash"]
