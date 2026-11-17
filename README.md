# cyberlab

An agent skill that sets up the **smallest isolated lab for one mission** and hands back trace files proven to show what was asked: an attack/benign pcap pair for a detection rule, or a capture of a protocol for a parser.

You (or a calling agent) say what the lab is for. The skill writes a one-goal mission brief, picks the smallest generator (a real-server Docker lab, or a crafted synthetic trace), writes what each trace must show as tshark expectations, runs the lab, tears it down and verifies the traces. No IDS, DPI or SIEM goes into the lab: the consumer replays the traces with its own tools.

## Install

Copy `skills/cyberlab/` into your agent's skills directory (for Claude Code: `~/.claude/skills/cyberlab/`), then:

```bash
~/.claude/skills/cyberlab/scripts/cyberlab doctor   # docker, compose, tools image
~/.claude/skills/cyberlab/scripts/cyberlab build    # builds cyberlab/tools:local (tcpdump, tshark, python3)
```

The host needs only Docker with Compose v2. Validated on macOS (arm64, Docker Desktop); Linux and Windows hosts have not been run yet.

## Use

```text
/cyberlab traces for an FTP brute-force rule: 5+ failed logins, and a normal login as benign
```

or from another skill: "use cyberlab to produce capture.pcap of <protocol> under tcp:port=<n> in <dir>".

The CLI underneath:

| Command | Does |
|---|---|
| `cyberlab templates` / `new <dir> --from <t>` | list / copy a lab template |
| `cyberlab check <lab>` | isolation policy on the resolved compose file |
| `cyberlab run <lab> <mode>` | policy, up, runtime isolation check, generate, capture (fails on dropped packets), verified teardown, verify `out/<mode>.pcap` |
| `cyberlab craft <lab> <trace> -- <args>` | synthetic trace with no network, then verify |
| `cyberlab verify <lab>` | check traces against `expect.json` |
| `cyberlab status` / `down <lab>` / `nuke` | list / stop one / remove every cyberlab lab |

## Templates (all run end to end)

| Template | Modes | Result on the reference run |
|---|---|---|
| `ftp-bruteforce` | attack, benign | 8 × `530` replies vs one `230` login (vsftpd) |
| `h2c-rapid-reset` | attack, benign | 100 RST_STREAM frames in ~47 packets vs 100 paced streams (nginx h2c) |
| `http-payloads` | attack, benign | Log4Shell, SQLi, traversal, XXE, Shellshock strings vs normal requests (nginx) |
| `port-scan` | attack, benign | 1,024 SYNs / 1,023 RSTs vs 5 HTTP requests |
| `protocol-capture` | capture | Redis RESP requests and replies, both directions, with an error reply |

## Safety

Every lab is checked before start (internal networks only, no published ports, no privileged or host namespaces, capabilities limited to NET_RAW/NET_ADMIN, no engine socket, bind mounts inside the lab), while running (networks internal, no ports, not privileged) and after teardown (nothing left). Isolation is Docker-level, not a VM: see `skills/cyberlab/references/safety.md`.

## Repository

| Path | Contents |
|---|---|
| `skills/cyberlab/` | the skill (SKILL.md, scripts, references, templates, tools image, evals) |
| `examples/mmt-workbench/` | an example *consumer* environment, not part of the skill: a Linux image with mmt-dpi, mmt-security and mmt-plugin that replays cyberlab traces (`detect.sh`) |

## Licence

Apache-2.0.
