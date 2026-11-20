# Crafted (synthetic) traces

Read this in Step 4 when the generator is **crafted**. `cyberlab craft` runs in the tools image with no network and writes `<lab>/out/<trace>`, its provenance (`origin: crafted (synthetic)`, the exact command, the sha256 of the lab's input files: everything but `out/`, `mission.md`, `mechanism.md`, `expect.json` and caches), the verification result and `out/<trace>.md`, the trace's reproduction document.

## craft_pcap.py (payloads behind real headers)

```bash
cyberlab craft <lab> capture.pcap -- --parent tcp:port=2208 --payloads-file payloads.txt
cyberlab craft <lab> capture.pcap -- --parent udp:dport=5684 --payload "40 01 00 01" --payload "s:60 45 00 01"
```

- `<lab>/payloads.txt` (paths are relative to the lab directory): one hex payload per line; `c:` client→server (default), `s:` server→client; `#` comments.
- Parents: `udp:port|dport|sport=N`, `tcp:port|dport|sport=N` (one TCP session: handshake, one segment per payload with correct sequence numbers and ACKs, FIN exchange), `ip:proto=N`, `ipv6:proto=N`, `ethernet:ethertype=N`.
- Output: classic pcap, Ethernet link type, checksums computed, frames 1 ms apart, `--repeat N` to repeat the list. Deterministic: the same arguments and payload file give the same bytes and sha256 on any host.
- Text protocols (XML, HTTP, SIP): hex-encode each message (`printf '%s' '<msg>' | xxd -p | tr -d '\n'`) or use a `--script` (*Crafted evidence traces* below).
- Write payloads from the specification or the attack description, before anything consumes the trace: every example, each message type, both directions, boundary values.

## Crafted evidence traces

A trace written by your own generator script, for evidence a lab cannot produce or payloads behind headers cannot express (several flows, odd flags, fragments).

**When to craft, and when not.** A rule keyed on IP addresses (IoCs) is not by itself a reason to craft: a fake-WAN lab gives the generator a TEST-NET stand-in for each address and a real session, and the consumer substitutes the stand-in for the IoC (`references/lab-authoring.md` → *Fake-WAN addresses*). Craft only when:

- the literal public address must appear in the trace bytes, and the consumer does not accept a stand-in plus a rule variable or substitution;
- no runnable client or server exists for the traffic; or
- the consumer asks for a synthetic trace.

Craft is not a route to other link layers: `verify` accepts only Ethernet, Linux cooked (SLL) and raw IP, and any other link type FAILs.

**Invocation.**

```bash
cyberlab craft <lab> <trace.pcap> --script <generator.py> [-- <script args>]
```

- `--script` must come right after the trace name. `<generator.py>` is a path relative to the lab directory, and the file must sit inside it. The `--` before the script's arguments is optional.
- `cyberlab craft <lab> <trace.pcap> -- <generator.py> …` does not run your script: without `--script` in that position, everything after `--` goes to `craft_pcap.py`, which requires `--parent`, so it stops with an argparse usage error, then `craft_pcap.py failed (above)` (exit 2).
- Before anything runs: the trace name uses only letters, digits, `.`, `_` and `-`, does not start with `.`, and ends in `.pcap`; the lab directory exists (no `docker-compose.yml` needed); the tools image is built (`cyberlab build`); and `<lab>/expect.json` lists the trace. Each failure exits 1.

**The `--script` contract.**

- It runs as `python3 /lab/<generator.py> <script args>` in the tools image (Alpine with `python3`, `tshark` and `tcpdump`; no pip packages), with `--network none`, no capabilities and your uid. The lab directory is mounted read-write at `/lab` and is the working directory; the skill's `scripts/` is mounted read-only at `/cyberlab`.
- `$OUT` holds the output path, `/lab/out/<trace.pcap>`, and is the only variable cyberlab sets. Write a non-empty pcap there; craft removes an existing `out/<trace.pcap>` first.
- Standard library only: nothing else is installed, and there is no network to install it. Reuse `craft_pcap.py`'s frame builders rather than hand-packing headers: `import sys; sys.path.insert(0, "/cyberlab"); import craft_pcap`.
- Keep it deterministic (no clock, no unseeded random) so the trace reproduces byte for byte. A script that derives a trace from another one in `out/` reproduces only from that same source trace, whose sha256 the provenance records.
- There is no timeout (`CYBERLAB_TIMEOUT` applies to `run` only).
- Failures, each exit 2: a non-zero exit from the script gives `craft script failed (above).`; nothing written at `$OUT` gives `craft: <lab>/out/<trace.pcap> was not written. A --script must write to $OUT.`

**Written automatically after the script.**

- The provenance sidecar `out/<trace-stem>.provenance.json`: `origin: crafted (synthetic)`, the generator (`python3 <generator.py> <args>`), the pasteable `command`, frames, sha256, the sha256 of the lab's input files, the tools image and its versions. Craft fails (exit 2) if it cannot be written. It prints `NOTE trace   out/<trace.pcap>: <N> frames, SYNTHETIC, provenance out/<trace-stem>.provenance.json`.
- Then `verify` checks the same expectations as for a lab trace and writes `out/verify.json` and the trace document `out/<trace-stem>.md` (Origin: **crafted (synthetic)**). Craft exits with verify's code. Timing, window and gap expectations prove nothing about real traffic on a crafted trace.

**Label it synthetic downstream.** Every report that uses a crafted trace calls it **synthetic** and cites the provenance `origin`: the brief's generator line, cyberlab's hand-off report, and the consuming skill's own reports and test evidence (e.g. security-rule-generator's). It is never presented as a capture.

## Rules

- Write an Ethernet link layer (verify also accepts Linux cooked and raw IP, nothing else) and, for TCP, a full handshake before payloads: dissectors classify flows from them.
- A crafted trace never replaces a lab capture silently (*Label it synthetic downstream* above).
- Timing, rate and segmentation claims cannot rest on a crafted trace.
- Imitating a documented attack (a published implant, a CVE proof of concept, a tool's packets): take every distinguishing field value from the cited source, name the source in `mechanism.md`, and write one expectation per documented field (e.g. the sequence/acknowledgement relation, flags, options). A crafted trace that differs from its source shows only how its author read it.
- Name who is who. `craft_pcap.py` writes a fixed client (`10.0.0.1`, `fd00::1`, MAC `02:00:00:00:00:01`) and server (`…2`), and the trace document labels them itself. A `--script` trace opens its `## <trace>.pcap` section of `mechanism.md` with a `Roles:` line naming each address it writes (`references/mission.md` → *Mechanism*); without it, `doc` can only say which host spoke first, and warns.
- A derived trace (an edited copy of a lab capture) states in its `Traces:` line what was changed. Its expectations check the changed fields, and the timing it claims (`gap_min` / `gap_max`, `window`).
