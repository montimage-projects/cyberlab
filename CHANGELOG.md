# Changelog

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
