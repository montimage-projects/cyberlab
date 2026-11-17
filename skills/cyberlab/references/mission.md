# Mission brief and expectations

Read this in Steps 1–3. A **mission** is one goal that ends in one or two trace files. Everything in the lab exists for that goal; anything else is left out.

Contents: [The brief](#the-brief) · [One goal](#one-goal) · [Choose the generator](#choose-the-generator) · [Expectations](#expectations) · [Mission shapes](#mission-shapes) · [Examples](#examples)

## The brief

Write `<lab>/mission.md` with exactly these lines (`ASSUMED:` in front of each value nobody stated):

```markdown
# Mission: <one sentence goal>
- Consumer: <who uses the traces: a person, or a calling skill/agent and what it does with them>
- Protocol: <protocol, transport and port, e.g. FTP over TCP 21; for a new protocol, its parent selector, e.g. tcp:port=2208>
- Traces: <file name> — <what must be visible in it>   (one line per trace; at most 2)
- Generator: <crafted | lab> — <why, from the table below>
- Server/client: <images or implementations used, with versions>   (lab only)
- Destination: <lab directory>; <where the consumer will copy the traces, if it said>
- Out of scope: <what this mission does not produce>
```

When the request comes from another skill or agent, derive every line from that request and do not ask questions: the caller already knows what it needs.

`ASSUMED:` marks a guess about the consumer's **need** (the protocol variant, a threshold, what must be visible). Implementation choices you make to serve a stated need (server image and version, client, ports) are decisions, not assumptions: write them on the `Generator:` and `Server/client:` lines with the reason, and do not mark them `ASSUMED:`. When a person asked and the protocol, the attack variant or the consumer is unknown, ask once in a single message; otherwise mark the value `ASSUMED:`.

## One goal

- One mission produces the traces for **one** goal: one attack (attack + benign), or one protocol's normal traffic. A second attack, protocol or tool is a second mission with its own lab directory.
- A lab has **one victim, one generator and one capture** sidecar. No IDS, DPI engine, SIEM or dashboard in the lab: the consumer replays the traces with its own tools afterwards.
- Prefer the template closest to the goal and change as little as possible.

## Choose the generator

Take the first row that matches:

| The consumer needs… | Generator | Why |
|---|---|---|
| timing, rate, thresholds, request/response order, or several messages packed per TCP segment | **lab** with a real server (required) | real servers add delays and real stacks pack frames; crafted traces hide both |
| normal traffic of a protocol that has an open-source server/client image | **lab** | a real implementation is evidence; a crafted trace only shows how the spec was read |
| only field values or payload patterns, one message per packet, and no runnable implementation (or the consumer asked for synthetic) | **crafted** (`cyberlab craft`) | deterministic, no network at all |

Crafted traces are **synthetic**: the provenance says so, and the hand-off report repeats it.

## Expectations

Write `<lab>/expect.json` **before** generating: `run` and `craft` refuse a trace with no expectation. Each trace lists tshark display filters with frame-count bounds:

```json
{
  "max_frames": 10000,
  "traces": {
    "attack.pcap": [
      {"filter": "ftp.response.code == 530", "min": 5},
      {"filter": "ftp", "min": 1, "endpoints": 2}
    ],
    "benign.pcap": [
      {"filter": "ftp", "min": 1, "endpoints": 2},
      {"filter": "ftp.response.code == 530", "max": 0}
    ]
  }
}
```

- `min` defaults to 1 (0 when `max` is given); `max` defaults to unbounded.
- `endpoints: N` requires N distinct sources among the matching frames: use 2 to prove both directions are present.
- `count_field` (and optional `count_value`) counts messages instead of packets: one TCP segment can carry many HTTP/2 frames, SCTP chunks or pipelined requests, and a frame count then undercounts. Example: `{"filter": "http2.type == 3", "count_field": "http2.type", "count_value": "3", "min": 90}`.
- Every trace is also checked for a readable file, Ethernet / Linux cooked / raw IP link type, and 1..`max_frames` frames.
- A **benign** trace must assert that the protocol is present (`min` ≥ 1), not only that the attack is absent: an empty benign trace proves nothing.
- Write the filters from the mission, never from what a trace happened to contain.
- Check that a dissector and its fields exist before using them: `docker run --rm --network none cyberlab/tools:local tshark -G protocols | grep -i <proto>` (or `-G fields`). Reading the field list touches no trace.
- When the protocol has no tshark dissector, filter on the transport: `tcp.port == 2208 && tcp.len > 0`, or `tcp.payload contains "<marker>"`.

## Mission shapes

| Shape | Traces | Default expectations |
|---|---|---|
| **Attack pair** (detection rule) | `attack.pcap`, `benign.pcap` from the same server | attack: the attack messages with a minimum count, both endpoints; benign: the protocol present with both endpoints, the attack marker `max: 0` |
| **Protocol capture** (parser/plugin) | `capture.pcap` | the protocol's payload frames under its parent, `endpoints: 2` (both directions), each message type the consumer named, `max_frames` 10000 |
| **Variant set** (one attack, several encodings) | `attack.pcap` holding every variant, `benign.pcap` | one expectation per variant marker |

## Examples

**A rule generator needs evidence for an FTP brute-force rule.** The caller states: FTP, failed logins in a time window, the rule must stay silent on a normal login.

- Mission: "Produce an attack/benign pair of FTP logins against a real FTP server: ≥5 failed logins in the attack, one successful login in the benign".
- Generator: lab (a time window needs real server delays).
- Template: `ftp-bruteforce`; expectations as in the JSON above.

**A protocol-plugin generator needs a capture of OCI-P on TCP 2208.** The caller states: the parent selector, the message types to exercise, that no public capture exists.

- Mission: "Produce one capture of OCI-P requests and responses under `tcp:port=2208`".
- Generator: crafted if no server implementation can be run (synthetic, said in the report), otherwise a lab with the implementation.
- Expectations: `tcp.port == 2208 && tcp.len > 0` with `endpoints: 2`, plus `tcp.payload contains "<command name>"` for each message type the caller listed.
