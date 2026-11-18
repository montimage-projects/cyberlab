# Building and adapting a lab

Read this in Step 4 when the generator is a lab. Start from the closest template (`cyberlab templates`), change only what the mission needs, then run `cyberlab check <lab>` until it prints `RESULT PASS`.

Contents: [The contract](#the-contract) · [Templates](#templates) · [Adapting](#adapting-a-template) · [Adding a trace](#adding-a-trace) · [Isolation policy](#isolation-policy) · [Failures seen before](#failures-seen-before)

## The contract

`cyberlab run <lab> <mode>` drives every lab the same way:

| Part | Requirement |
|---|---|
| `name:` | `cyberlab-<lab>` (`cyberlab new` sets it; teardown and `nuke` find labs by it) |
| network | one network: `driver: bridge`, `internal: true`, `driver_opts: { com.docker.network.bridge.inhibit_ipv4: "true" }`; no `ports:` anywhere |
| `victim` | the server under test, on the lab network |
| `capture` | `image: ${CYBERLAB_TOOLS:-cyberlab/tools:local}`, `network_mode: "service:victim"`, `tcpdump -Z root -i eth0 -B 32768 --immediate-mode -U -w /cap/${PCAP}.pcap <bpf>`, healthcheck `test -s /cap/${PCAP}.pcap` (the trace stays inside the container until `run` copies it to `out/`) |
| `generator` | the client/attacker; reads `${MODE}`, `depends_on` capture `service_healthy`, sleeps ~2 s, does its work, **exits 0** on success and non-zero on failure |

`run` checks the policy, starts the lab, checks the running containers and network, waits for `generator` (`CYBERLAB_TIMEOUT`, default 300 s), waits 2 s for libpcap to flush, stops `capture` and fails if tcpdump reports any packet dropped by the kernel, tears everything down, checks nothing is left, writes `out/<mode>.pcap`, `out/<mode>.provenance.json` and `out/<mode>.generator.log`, then verifies the trace against `expect.json`.

## Templates

| Template | Modes | Pattern it shows |
|---|---|---|
| `ftp-bruteforce` | attack, benign | victim **built** from a pinned base (`victim-image/`); stdlib client on `python:3.12-slim` |
| `h2c-rapid-reset` | attack, benign | generator image **built** from `./generator-image` when a library is needed; cleartext h2c |
| `http-payloads` | attack, benign | attack strings from `payloads/<mode>.jsonl`; the victim executes nothing |
| `port-scan` | attack, benign | stdlib socket scan; capture of all TCP |
| `protocol-capture` | capture | a protocol's own server and client (Redis example) exercising every message type |

## Adapting a template

1. Victim: the server image the mission names, pinned to a version tag (or a digest). Mount its config read-only from the lab directory.
2. Generator: the smallest client that produces the traffic. Standard library on `python:3.12-slim` when possible; otherwise a `build:` directory whose Dockerfile installs pinned packages (the build has network access, the running lab does not).
3. Modes: one `MODE` value per trace (the trace name without `.pcap`); the same server for every trace. An unknown mode must make the generator exit non-zero, never fall back to another mode's traffic.
4. Capture filter: the protocol's port only, so the trace stays small and on-mission.
5. `expect.json`: written from the mission before the first run (`references/mission.md`).

## Adding a trace

In a lab that already holds traces (a continued mission):

1. Pick a new trace name, e.g. `attack-slow.pcap`; its mode is `attack-slow`.
2. Add the mode to the generator: a new branch in the client (`ftp-bruteforce`, `port-scan`, `h2c-rapid-reset`, `protocol-capture/gen.sh`), or a new `payloads/attack-slow.jsonl` (`http-payloads`). Leave the existing branches as they are, so earlier traces can still be regenerated identically.
3. Change the victim, its config or the capture filter only if every existing trace is still served by the change; otherwise the new need is a different task (a new lab). Say in the hand-off which change was made after which trace.
4. Add the trace's entry to `expect.json`, then `cyberlab check <lab>` (it checks every mode) and `cyberlab run <lab> attack-slow`.

## Isolation policy

`cyberlab check` (and `run`, before starting) refuses a lab containing a symlink, then resolves the compose file with `MODE`/`PCAP` set to each mode of `expect.json` and checks it against an **allowlist**; any key or value not listed fails:

- top level: `name` (`cyberlab-*`), `services`, `networks`, `volumes`;
- networks: `driver: bridge`, `internal: true`, `driver_opts` exactly `com.docker.network.bridge.inhibit_ipv4: "true"` (no host address on the bridge: see `references/safety.md`), the default name, no ipam, no external network;
- services: `image`, `build` (context inside the lab; `dockerfile`, `args`, `target` only), `command`, `entrypoint`, `environment`, `working_dir`, `user`, `depends_on`, `healthcheck`, `labels`, `hostname`, `expose`, `tmpfs`, `read_only`, `init`, `stop_grace_period`, `stop_signal`, `platform`, `pull_policy`, `stdin_open`, `tty`, `cap_add` (NET_RAW/NET_ADMIN), `cap_drop`, `networks` (declared ones), `network_mode` (`service:<lab service>` or `none`), `volumes` (bind inside the lab, declared lab volumes, tmpfs; never an engine socket), `restart: "no"`;
- runner contract: `generator` and `capture` exist; `capture` uses the tools image, runs `tcpdump … -w /cap/<trace>`, shares a lab service's network namespace and mounts nothing — so only tcpdump can produce the trace that `run` copies out.

It warns (does not fail) on an image without a pinned tag. While running, `run` also checks every lab network is internal with `inhibit_ipv4`, every network each container joins is internal, and that no container publishes ports, is privileged or uses the host network.

## Failures seen before

| Symptom | Cause | Fix |
|---|---|---|
| Empty or tiny trace | capture stopped right after the generator, or the generator ran before tcpdump | keep the healthcheck + `depends_on: service_healthy`, the generator's initial sleep; `run` adds the 2 s grace |
| Generator exits non-zero with DNS/pip errors | `pip install` at run time on the internal network | use the standard library, or install in a built image |
| Protocol fields missing in the trace | TLS (443, FTPS, HTTPS) | use the cleartext variant of the protocol |
| Window/rate expectations fail on crafted traces | crafted timing is compressed | use a lab with the real server |
| `the capture dropped N packet(s)` | a burst outran tcpdump (seen when it wrote through a bind mount on Docker Desktop) | write to `/cap` inside the capture container as the templates do, raise `-B`, or pace the generator; never keep an incomplete trace |
| Lab left running after an interruption | the run was killed | `cyberlab down <lab>`, or `cyberlab nuke` |
