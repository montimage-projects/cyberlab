# Mission brief and expectations

Read this in Steps 1–3. A **mission** is one task: one protocol or one attack, for one consumer. It has one lab directory and as many trace files as the task needs. Everything in the lab exists for that task; anything else is left out. Later requests on the same task add traces to the same lab.

Contents: [The brief](#the-brief) · [One task per lab](#one-task-per-lab) · [Continue or start](#continue-or-start) · [Choose the generator](#choose-the-generator) · [Expectations](#expectations) · [Mechanism](#mechanism) · [Mission shapes](#mission-shapes) · [Examples](#examples)

## The brief

Write `<lab>/mission.md` with exactly these lines (`ASSUMED:` in front of each value nobody stated):

```markdown
# Mission: <one sentence goal>
- Scope: <the task boundary later requests are tested against: protocol, attack or behaviour, server; e.g. "FTP brute force against vsftpd/proftpd, for an mmt-security rule">
- Consumer: <who uses the traces: a person, or a calling skill/agent and what it does with them>
- Protocol: <protocol, transport and port, e.g. FTP over TCP 21; for a new protocol, its parent selector, e.g. tcp:port=2208>
- Traces: <file name> — <what must be visible in it>; [rule <N>: <its condition and threshold, e.g. >20 A-ASSOCIATE-RQ in 5 s>; fires | stays silent]   (one line per trace; as many as the task needs; the rule part when the consumer named a rule)
- Generator: <crafted | lab> — <why, from the table below>
- Server/client: <images or implementations used, with versions>   (lab only)
- Destination: <lab directory>; <where the consumer will copy the traces, if it said>
- Out of scope: <what this mission does not produce>

## Log
- <YYYY-MM-DD>: <request in one line> → <trace names added or regenerated>
```

The `## Log` keeps the history of a reused lab: one dated line per request, added at the end.

When the request comes from another skill or agent, derive every line from that request and do not ask questions: the caller already knows what it needs.

`ASSUMED:` marks a guess about the consumer's **need** (the protocol variant, a threshold, what must be visible). Implementation choices you make to serve a stated need (server image and version, client, ports) are decisions, not assumptions: write them on the `Generator:` and `Server/client:` lines with the reason, and do not mark them `ASSUMED:`. When a person asked and the protocol, the attack variant or the consumer is unknown, ask once in a single message; otherwise mark the value `ASSUMED:`.

## One task per lab

- One mission serves **one** task: one attack (its attack traces and the benign traffic it must stay silent on), or one protocol's traffic for a parser. Inside that task, add as many traces as the work needs: attack variants, thresholds, error cases, more benign profiles, another message type.
- A second attack, protocol or unrelated tool is a second mission with its own lab directory.
- A lab has **one victim, one generator and one capture** sidecar. No IDS, DPI engine, SIEM or dashboard in the lab: the consumer replays the traces with its own tools afterwards.
- Prefer the template closest to the goal and change as little as possible.

## Continue or start

Before writing a brief, look for a lab to continue:

1. The caller names a lab directory:
   - no `mission.md` there → start the mission in it;
   - its `Scope:` covers the request → continue it;
   - it does not → never write into it: ask once (a person) or return BLOCKED naming the mismatch (a calling skill).
2. Otherwise run `cyberlab labs` and compare each `Scope:` line with the request.
   - Same protocol and same task (a new variant, threshold, error case or benign profile of it) → continue that lab.
   - Different protocol, different attack, or a consumer with an unrelated goal → start a new lab.
   - Unclear, and a person asked → ask once, naming the candidate lab and its scope. A calling skill never gets a question: if it named no lab, start a new one.
3. Continuing a lab:
   - Keep the goal and scope; a lab written before `Scope:` existed gets one now, derived from its goal and `Protocol:` lines (log it). Add the new traces under `Traces:` and a `## Log` line.
   - Give each new trace a name not yet in `out/` that says what it shows (`attack-slow.pcap`, `benign-anon.pcap`, `capture-errors.pcap`). Reusing a name regenerates that trace and overwrites its file and provenance: do it only when asked.
   - Do not change what existing modes send or what existing expectations check; add new modes and new entries.
   - A request that would widen the scope (another server for the same attack, say) belongs to the lab only if the scope line already covers it; otherwise ask (a person) or start a new lab (a caller).

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
- **Every claim in a `Traces:` line gets an expectation**, tagged with `"claim"`. An unchecked claim is how a trace ends up showing something else than its description. Map each kind of claim to a check:

  | Claim in the brief | Expectation |
  |---|---|
  | a count ("8 failed logins", "1,024 SYNs") | `min` / `max` |
  | a rate or time window ("30 associations in 3 s", "100 CAM in 1 s") | `window` with `min` (most matches in any T-second window) |
  | a pacing ("one attempt every 20 s", "1 ms apart", "2 s later") | `gap_min` / `gap_max` |
  | variety ("different ports", "4 station IDs", "8 PORT arguments") | `distinct` with `min` |
  | a relation between fields ("to a third host", "spoofed source", "same NAS SQN") | a field comparison in the filter: `ftp.active.cip != ip.src`, `ip.src != 10.0.0.2` |
  | a variant or marker (each payload, each message type, each reply type) | one filtered expectation per variant |
  | both directions | `endpoints: 2` |

- **Rule thresholds.** When the consumer named a rule, read its condition (`Traces:` line, or the rule itself when you have it) and check it from both sides:
  - an attack trace exceeds the threshold inside the rule's own window, e.g. `{"filter": "<the rule's event>", "window": 5, "min": 21}` for ">20 in 5 s";
  - a benign or control trace stays under every condition the rule tests, with the same filter and window and `"max": <threshold>`. The absence of the attack marker is not enough: a benign trace that meets the rule's condition is an attack trace for that rule.
  - If the rule's logic would match a benign trace whatever the traffic (a check on a field normal traffic always has), keep the trace, write `max` for what the trace really is, and report the rule's limit under Uncertainty.
- Check that a filter compiles and selects what you mean before relying on it (`$` followed by `{` starts a tshark macro: match `jndi:` instead of `${jndi:`; presence-flag fields such as `tcp.options.sack_perm` never equal 1, so test them bare; a filter like `ip.dst != ip.src` matches every frame): an expectation that matches nothing proves nothing (`max: 0` on a misspelt field always passes). Unknown keys fail the check.
- Check that a dissector and its fields exist before using them: `docker run --rm --network none cyberlab/tools:local tshark -G protocols | grep -i <proto>` (or `-G fields`). Reading the field list touches no trace.
- When the protocol has no tshark dissector, filter on the transport: `tcp.port == 2208 && tcp.len > 0`, or `tcp.payload contains "<marker>"`.

## Mechanism

Write `<lab>/mechanism.md` in Step 4, and correct it in Step 6 against what each trace really holds. Every trace document (`out/<trace>.md`) shows it under **Mechanism**, so a reader learns what the attack is without leaving the trace. Each template ships one to adapt. `cyberlab doc` prints a `WARN doc` line when the file, a trace's section or the references are missing.

```markdown
# Mechanism: <attack or protocol name, with its CVE if it has one>

<How it works: what the attacker sends, which protocol rule or weakness it abuses, and what that leads to.
What a detector keys on: the messages, fields, counts or timing that set it apart from normal traffic; for a rule the caller named, what that rule matches (read its source when you have it) and its thresholds.
How this lab produces it: server, client, any change from the real-world attack (e.g. cleartext instead of TLS).>

## <trace>.pcap
<what this trace holds: the variant, the counts, the pacing; the rule(s) it targets and the expected verdict (fires / stays silent); for a benign trace, what normal use it shows and why it must not trigger the rule; whether it is a real capture or synthetic>

## References
- [<title>](<url>) — <what this source supports>
```

- A protocol capture describes the protocol instead: its messages and fields, and the cases the trace covers.
- One `## <trace>.pcap` section per trace. A continued lab adds sections and leaves the others unchanged.
- References: link the primary sources first. That means the standard (RFC or 3GPP spec), the vulnerability record (NVD CVE page), the technique (MITRE ATT&CK, CWE, CAPEC), and the vendor or researcher write-up. For a detection rule, add the rule's own documentation if the caller gave it.
- Cite only what you know is real. When web access exists, open each link and check its content, not only its status. A 200 response can be a bot-check or home page, and PDFs have no title:
  - HTML page: its title or text names what you cite;
  - PDF or plain-text file: the fact you cite is in it;
  - NVD CVE page (`https://nvd.nist.gov/vuln/detail/CVE-…`): curl gets a bot page, so check the CVE with `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-…` and link the detail page;
  - a rule or source file in a repository: link it only on a public branch where it exists.

  Drop a link that fails these checks. Without web access, put `(link not checked)` after each link. Never invent a URL, a CVE number or a technique ID. When there is no public source, write `No public reference found.` under `## References`.
- Describe the mechanism, not a working exploit. Give the bytes and behaviour a detector needs, and nothing more (`references/safety.md`).

## Mission shapes

| Shape | Traces | Default expectations |
|---|---|---|
| **Attack pair** (detection rule) | `attack.pcap`, `benign.pcap` from the same server | attack: the attack messages with a minimum count (and `window` above the rule's threshold), both endpoints; benign: the protocol present with both endpoints, the attack marker `max: 0`, and the rule's event under its threshold in the same `window` |
| **Protocol capture** (parser/plugin) | `capture.pcap` | the protocol's payload frames under its parent, `endpoints: 2` (both directions), each message type the consumer named, `max_frames` 10000 |
| **Variant set** (one attack, several encodings) | `attack.pcap` holding every variant, `benign.pcap` | one expectation per variant marker |
| **Growing set** (a reused lab) | the traces above plus one per later request: `attack-<variant>.pcap`, `benign-<profile>.pcap`, `capture-<case>.pcap` | each new trace gets its own entry; existing entries stay as they are |

A variant set fits one trace when the consumer wants all variants at once; split them into one trace per variant when the consumer tests them separately.

## Examples

**A rule generator needs evidence for an FTP brute-force rule.** The caller states: FTP, failed logins in a time window, the rule must stay silent on a normal login.

- Mission: "Produce an attack/benign pair of FTP logins against a real FTP server: ≥5 failed logins in the attack, one successful login in the benign". Scope: "FTP brute force against a real FTP server, for an mmt-security rule".
- Generator: lab (a time window needs real server delays).
- Template: `ftp-bruteforce`; expectations as in the JSON above.
- A week later the caller wants a slow brute force (one attempt every 20 s) to test the rule's window. Same scope → same lab: add `attack-slow.pcap` to the brief, an `attack-slow` mode to the generator, its expectations, and a `## Log` line; `attack.pcap` and `benign.pcap` stay untouched.
- The caller then asks for an SSH brute force. Different protocol → a new mission and lab.

**A protocol-plugin generator needs a capture of OCI-P on TCP 2208.** The caller states: the parent selector, the message types to exercise, that no public capture exists.

- Mission: "Produce one capture of OCI-P requests and responses under `tcp:port=2208`".
- Generator: crafted if no server implementation can be run (synthetic, said in the report), otherwise a lab with the implementation.
- Expectations: `tcp.port == 2208 && tcp.len > 0` with `endpoints: 2`, plus `tcp.payload contains "<command name>"` for each message type the caller listed.
