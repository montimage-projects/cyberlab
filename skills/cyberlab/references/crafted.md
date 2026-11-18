# Crafted (synthetic) traces

Read this in Step 4 when the generator is **crafted**. `cyberlab craft` runs in the tools image with no network and writes `<lab>/out/<trace>`, its provenance (`origin: crafted (synthetic)`, the exact command, the sha256 of every lab file), the verification result and `out/<trace>.md`, the trace's reproduction document.

## craft_pcap.py (payloads behind real headers)

```bash
cyberlab craft <lab> capture.pcap -- --parent tcp:port=2208 --payloads-file payloads.txt
cyberlab craft <lab> capture.pcap -- --parent udp:dport=5684 --payload "40 01 00 01" --payload "s:60 45 00 01"
```

- `<lab>/payloads.txt` (paths are relative to the lab directory): one hex payload per line; `c:` client→server (default), `s:` server→client; `#` comments.
- Parents: `udp:port|dport|sport=N`, `tcp:port|dport|sport=N` (one TCP session: handshake, one segment per payload with correct sequence numbers and ACKs, FIN exchange), `ip:proto=N`, `ipv6:proto=N`, `ethernet:ethertype=N`.
- Output: classic pcap, Ethernet link type, checksums computed, frames 1 ms apart, `--repeat N` to repeat the list. Deterministic: the same arguments and payload file give the same bytes and sha256 on any host.
- Text protocols (XML, HTTP, SIP): hex-encode each message (`printf '%s' '<msg>' | xxd -p | tr -d '\n'`) or use a `--script`.
- Write payloads from the specification or the attack description, before anything consumes the trace: every example, each message type, both directions, boundary values.

## A custom script

When the trace needs more than payloads behind headers (several flows, odd flags, fragments):

```bash
cyberlab craft <lab> attack.pcap --script gen.py -- <args>
```

`gen.py` sits in the lab directory, runs with `python3` (standard library only) in the tools image with no network, and must write the pcap to the path in the `OUT` environment variable. Keep it deterministic (no clock, no unseeded random) so the trace reproduces byte for byte; a script that derives a trace from another one in `out/` reproduces only from that same source trace, whose sha256 the provenance records. Reuse `craft_pcap.py`'s frame builders rather than hand-packing headers: `import sys; sys.path.insert(0, "/cyberlab"); import craft_pcap` (the skill's `scripts/` is mounted read-only at `/cyberlab`).

## Rules

- Always an Ethernet link layer and, for TCP, a full handshake before payloads: dissectors classify flows from them.
- A crafted trace never replaces a lab capture silently: the brief's generator line and the hand-off report both say **synthetic**.
- Timing, rate and segmentation claims cannot rest on a crafted trace.
- Imitating a documented attack (a published implant, a CVE proof of concept, a tool's packets): take every distinguishing field value from the cited source, name the source in `mechanism.md`, and write one expectation per documented field (e.g. the sequence/acknowledgement relation, flags, options). A crafted trace that differs from its source shows only how its author read it.
- A derived trace (an edited copy of a lab capture) states in its `Traces:` line what was changed. Its expectations check the changed fields, and the timing it claims (`gap_min` / `gap_max`, `window`).
