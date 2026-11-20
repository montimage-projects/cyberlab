# Changelog

## Unreleased

### Features

- Clean up lab images after a mission, with confirmation. `cyberlab down <lab> --images` also removes the images compose built for that lab, and `cyberlab nuke --images` removes every image built for a cyberlab lab; pulled images and the tools image are never touched. `cyberlab status` now lists those built images too, so it stays the dry run. The skill's hand-off ends by showing the lab's built images and removing them only after the person says yes; a calling skill with nobody to ask keeps them and names them in the report.

## v1.3.0 — 2026-11-19

### Features

- Ask where to store the output. For a new lab, a person who names no location is asked in the agent's single Step 1 message, with the default offered: `<invocation directory>/<YYYYMMDD-HHMMSS>-<slug>`, in the directory the skill was invoked from. A calling skill, or a run with nobody to answer, gets that default without a question.
  - A named directory that is missing or empty becomes the lab; one that holds other files gets the lab in a subdirectory, so lab files never mix with a project's.
  - New labs no longer go under `~/.cache/cyberlab` (`CYBERLAB_HOME`). `cyberlab labs` takes several directories; with none it lists the current directory and that older location, so labs made before 1.3.0 can still be continued.
  - The brief's `Destination:` line and the hand-off's `Lab:` line say where the output is and whether it was named or the default.
- Say who is who before any detail. `cyberlab run` records the IPv4, IPv6 and MAC address Docker gave each lab service while the lab runs (`NOTE address generator=…, victim=…`, and `addresses` in the provenance).
  - Each trace document opens with a **Who is who** section: the attacker (or client), the victim (or server) and every other address in the trace (broadcast, multicast, spoofed or third party), with its role, MAC, lab service, image and frame counts, as a table and a Mermaid flowchart. The generator is called the attacker only in attack traces.
  - Crafted traces take their roles from `craft_pcap.py`'s fixed addresses, or from a `Roles: attacker = <address>, …` line at the top of the trace's section in `mechanism.md`. Without either, the document names only the initiator and the responder, never a guessed attacker, and `doc` warns.
  - `mechanism.md` opens with who is who, by lab service name: Docker assigns new addresses on every run, so they appear only in the trace documents.
  - The hand-off report gains a `Who:` line before the traces.
- Explain with diagrams first, in every document:
  - Trace documents draw the exchange (a sequence diagram of the first 30 frames that carry it: payloads, non-TCP frames, connection openings and resets), the traffic over time (frames per time bin), the protocol mix, and how the trace was generated, as Mermaid diagrams. The raw tshark summaries move into a folded block.
  - `mechanism.md` explains the attack, and what each trace holds, with Mermaid sequence diagrams and short text. The five templates ship them.
  - `doc` warns when `mechanism.md` or a trace's section has no diagram, and when a diagram has a mistake that stops it rendering: a `;` in a sequence message, a block without its `end`, an unquoted flowchart label with parentheses.
  - Checked by rendering with mermaid-cli 12: all 632 diagrams in the documents of 110 existing traces (lab captures, crafted traces, ARP, IPv6, SCTP, nested tunnels) and of 12 new ones (every template mode, a second FTP run, a `craft_pcap.py` trace and one agent test run), with no failure.
- Write a reproduction document for every trace: `out/<trace>.md` says what the trace contains, how it was generated, what was checked and how someone else reproduces it.
  - `run`, `craft` and `verify` write it; the new `cyberlab doc <lab> [trace.pcap]...` writes it for traces made before documents existed. Their documents mark the lab file hashes as taken at that time, not at generation.
  - The document is built from the trace's `Traces:` line in `mission.md`, its `expect.json` entry, `out/verify.json`, its provenance, and tshark summaries: protocol hierarchy, conversations and the first 40 packets.
  - It states what reproducing means for the trace. A trace crafted with `craft_pcap.py` gives the same bytes and sha256 (checked by crafting a trace twice). A lab capture gives an equivalent trace that passes the same expectations, never the same file. A `--script` trace gives the same file only if the script is deterministic.
- Explain the attack in every trace document: a lab's `mechanism.md` describes how the attack (or, for a protocol capture, the protocol) works, what each trace shows of it, and the references. The document shows it under **Mechanism**.
  - Every template ships one with checked links: RFC 959, MITRE ATT&CK T1110.001 and CWE-307 (FTP brute force); CVE-2023-44487, RFC 9113 and Cloudflare's write-up (HTTP/2 Rapid Reset); CVE-2021-44228, CVE-2014-6271, OWASP and T1190 (HTTP payloads); the Nmap guide, T1046 and RFC 9293 (port scan); the RESP spec (Redis capture).
  - The skill writes or adapts it in Step 4. It cites only sources whose content it has checked (or marks a link `(link not checked)`) and never invents a URL, CVE or technique ID.
  - Each trace section names the rule it targets and the expected verdict (fires / stays silent).
  - In Step 6 the skill checks the text against the trace actually captured. A difference that breaks the mission sends the trace back to Step 5, not into the text.
- `expect.json` can check what a time-window rule keys on: `window` (the most matches in any T-second window), `distinct` (distinct values of a field), `gap_min` / `gap_max` (spacing between consecutive matches), and `claim` (the sentence of the brief an expectation proves). Unknown keys now fail the check instead of being ignored.
- Close the workflow gaps that let traces differ from their description (found by documenting 108 existing traces):
  - Every claim in a `Traces:` line gets an expectation: a count, rate, pacing, variety, relation between fields or variant.
  - A rule the consumer named is checked from both sides: the attack above its threshold in the rule's window, the benign trace under it.
  - Capture filters keep the replies the traffic causes, e.g. ICMP for UDP or IP-level traffic.
  - Adapting a template removes the template's leftovers.
  - Crafted traces that imitate a documented attack take their field values from the source.
  - The hand-off says verdicts are expected, not confirmed by running the detector.
- Fixes found while regenerating 108 traces under the new checks:
  - `distinct: "ip.src"` (or any field also used for the source column) counted 0, because tshark prints a repeated field once.
  - `window` and `distinct` in one expectation silently ignored `distinct`; the combination now fails with a message.
  - `craft` could fail with FileNotFoundError when writing the provenance or document right after the host deleted it (Docker Desktop bind mount). Files are now written atomically and not deleted on the host first.
  - `cyberlab verify <lab> --trace X` broke the document step; `--trace` is now accepted.
  - `doc` warns when a trace made by a `--script` craft may derive from another trace that has changed since.
  - Lab authoring documents the Docker bridge IGMP race; the expectations guide documents presence-flag fields and always-true field comparisons.
- `cyberlab doc` (and `run`, `craft`, `verify`) prints a `WARN doc` line for each gap in a trace's document: no `Traces:` line, no `mechanism.md` or section, no references, not verified or failing, lab inputs not recorded or changed since generation. Step 6 requires none for the request's traces.
- Record what reproduction needs in `out/<trace>.provenance.json`:
  - the cyberlab version, the exact command, and `MODE`/`PCAP`/`CYBERLAB_TIMEOUT`;
  - the sha256 of every lab file at generation;
  - the resolved lab services, and image IDs with registry digests and platform;
  - the Dockerfile base images, the tools image and its tshark/tcpdump/Python versions, and the host's Docker version and platform;
  - for `--script` crafts, the sha256 of the other traces in `out/` that the script may have read.

  Existing fields are unchanged. The document flags any lab file changed after its trace was generated.

### Bug Fixes

- A line starting with `#` inside a code block of `mechanism.md` was read as a heading, which could cut a section or replace the title. Code fences are now respected.
- A `Roles:` line in `mechanism.md` that named a host by its MAC address did not resolve when that host also sent IP frames, so `doc` warned that it matched no address and the Who is who table listed the host as "Other". The MAC now resolves to the host's address when the MAC sent from only that address (or one IPv4 and one IPv6 address) and no other MAC sent from it. In a spoofed trace, where a MAC sends for several addresses or shares one with another MAC, the warning stays and says why: name such a host by its IP address.
- A trace crafted by a `--script` that reads another trace of the lab (such as a `derive.py` that edits `out/benign.pcap`) was described as having addresses the generator wrote, with "no host or network was involved". Its Who is who section now names the source trace (and whether it is a lab capture), and the diagram title and the "Other" rows no longer say the addresses were invented. Traces written from scratch keep the old wording.
- `craft` and `run` fail when the provenance step fails. Before, a re-craft kept the previous trace's `provenance.json` (with the old sha256, command and inputs) next to the new trace and exited 0. They now check the step's exit status and remove the stale provenance and document.
- The comment at the top of a trace document named the cyberlab version that generated the trace, not the one that wrote the document, so `cyberlab doc` run by 1.3.0 on a 1.2.0 trace said `Generated by cyberlab 1.2.0`. It now reads `Written by cyberlab <version that wrote it>`. The summary table's `cyberlab` row still gives the trace's own version and adds `(document written by …)` when the two differ.

### Documentation

- Put onboarding first in the README: install, one-time setup, the common agent request, what comes back and how to replay it, then the CLI-only path. The problem, diagrams, features, templates and safety come after; the duplicate "Get started" section is gone.
- Add the cyberLab logo: a sealed lab with a captured trace that ends in a check mark, in the MMT amber palette. `assets/logo/` holds 9 SVG variants (mark, full, full for dark backgrounds, badge, wordmark, app icon, favicon, white, black), PNG exports in `assets/logo/png/`, and `brand-showcase.html`. The README header shows the badge (the logo on its own dark tile, with outlined text), which reads the same whatever the GitHub or system theme.
- Add a lab topology section to the README: a Mermaid diagram of the victim, generator and capture containers, the no-network tools containers and the consumer, with arrows for packets, the capture tap and files, and a table of each container's role, network and images. Detailed reference material moves into collapsed sections.

**Full Changelog**: https://github.com/montimage-projects/cyberlab/compare/v1.2.0...v1.3.0

## v1.2.0 — 2026-11-18

First release of cyberlab, an agent skill that builds the smallest isolated Docker lab for one mission and returns pcap traces verified to show what was asked. The skill's internal versions 1.0.0 and 1.1.0 were never tagged; their changes are included below.

### Features

- Add the cyberlab skill: describe what a lab is for, get the smallest isolated Docker lab for that one mission, and receive traces checked against written expectations ([7e8ebf9](https://github.com/montimage-projects/cyberlab/commit/7e8ebf9)) @luongnv89
  - Agent workflow in `SKILL.md` (Steps 0–6): mission brief, smallest-generator rule (a real-server lab for timing, rate, order or real framing; a crafted trace only when no runnable implementation exists), expectations first, and a hand-off report (Result, Traces, Evidence, Uncertainty, Decision).
  - `expect.json` holds tshark filters with frame-count bounds per trace; `run` and `craft` refuse a trace that has no expectation, and `verify` writes `out/verify.json`.
  - Isolation is checked three times: an allowlist policy on the resolved compose file (`lab_policy.py`), a runtime check of the running containers and networks, and a verified teardown.
  - `run` fails when the capture drops packets. Every trace gets `out/<trace>.provenance.json` with its origin, frame count, sha256 and, for lab captures, the images used.
  - CLI `scripts/cyberlab`: `doctor`, `build`, `templates`, `new`, `check`, `run`, `craft`, `verify`, `status`, `down`, `nuke`; exit codes `0`/`1`/`2`; `CYBERLAB_TOOLS` and `CYBERLAB_TIMEOUT` settings.
  - Five lab templates: `ftp-bruteforce`, `h2c-rapid-reset`, `http-payloads` (Log4Shell, SQLi, traversal, XXE and Shellshock strings vs normal requests), `port-scan`, and `protocol-capture` (Redis RESP).
  - Crafted traces (`craft_pcap.py`): payloads behind real Ethernet/IP/TCP/UDP headers, written with no network and labelled synthetic; `craft --script` runs your own generator script from the lab directory.
  - Tools image `cyberlab/tools:local` (tcpdump, tshark, Python 3) runs every check, so the host needs only Docker with Compose v2.
  - `examples/mmt-workbench`: an example consumer that replays traces through mmt-dpi and mmt-security (not part of the skill).
  - Agent-behaviour evals in `evals/evals.json`.
- Make labs mission-scoped and reusable for the same task ([#3](https://github.com/montimage-projects/cyberlab/pull/3)) @luongnv89
  - A mission is one task (one protocol or attack, for one consumer). Its lab holds as many traces as the task needs instead of at most two; later requests on the same task add traces to the same lab, and an unrelated task gets its own lab.
  - `mission.md` gains a `Scope:` line, which later requests are tested against, and a dated `## Log` of requests.
  - New `cyberlab labs [dir]` lists mission labs (goal, scope, traces) under `$CYBERLAB_HOME` (default `~/.cache/cyberlab`) to find one to continue.
  - New traces get new names and generator modes; existing traces, modes and expectations stay untouched. The final `verify` rechecks every trace in the lab, and the hand-off report gains a `Lab:` line for the earlier traces.
  - A named lab whose scope does not cover the request is never written into: a person gets one question, a calling skill gets BLOCKED naming the mismatch.
  - The `h2c-rapid-reset` and `protocol-capture` generators now exit with an error on an unknown mode instead of producing another mode's traffic; `protocol-capture` now passes `MODE` to `gen.sh`.
  - `cyberlab new` on a directory that already holds a lab now explains how to add traces to it.
  - Evals for continuing a lab, an unrelated task, and a named lab with a scope mismatch.

### Bug Fixes

- Fix lab isolation on Linux hosts: with `internal: true` alone, a lab could reach SSH and 9 other host services through the bridge gateway ([69f8aef](https://github.com/montimage-projects/cyberlab/commit/69f8aef)) @luongnv89
  - The policy (`check`, `run`) and the runtime check now require `driver_opts: { com.docker.network.bridge.inhibit_ipv4: "true" }` on every lab network, and every template sets it. With it, the host has no address on the lab bridge, and host ports, public IPs and DNS are unreachable from a lab.
  - Escape tests passed on macOS arm64 (Docker Desktop) and Ubuntu 24.04 arm64 (Docker Engine); `references/safety.md` explains the option.
- Fix intermittent `ftp-bruteforce` failures: vsftpd segfaulted (exit 139) under repeated failed logins on arm64 Linux ([69f8aef](https://github.com/montimage-projects/cyberlab/commit/69f8aef)) @luongnv89
  - The victim is now ProFTPD on a pinned Debian 12 base, with the server's real delay on failed logins.
  - The client tolerates dropped sessions and fails only when the mode's goal is not met: fewer than 5 `530` replies (attack) or no successful login (benign).

### Documentation

- Expand the README for the open-source release: features, how-it-works diagram, quick start, full CLI reference with exit codes, configuration, project structure, contributing and acknowledgments ([#1](https://github.com/montimage-projects/cyberlab/pull/1)) @luongnv89
- Document one-command installs with `npx skills add` (Vercel skills CLI) and `asm install` (agent-skill-manager) ([#2](https://github.com/montimage-projects/cyberlab/pull/2)) @luongnv89

### Other Changes

- Ignore the local `.oss-ready/` scratch folder in git ([2ba4dc5](https://github.com/montimage-projects/cyberlab/commit/2ba4dc5)) @luongnv89

**Full Changelog**: https://github.com/montimage-projects/cyberlab/commits/v1.2.0
