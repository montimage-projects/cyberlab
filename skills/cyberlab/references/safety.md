# Safety and threat model

Read this in Step 0 the first time cyberlab runs on a machine, and before any mission whose payload could do harm outside the lab.

## What cyberlab enforces

| Layer | Check | Where |
|---|---|---|
| Before start | allowlist policy on the resolved compose file (internal networks with `inhibit_ipv4`, a custom subnet only inside a TEST-NET range, no ports, no privileged or host namespaces, caps limited to NET_RAW/NET_ADMIN, no engine socket, bind mounts inside the lab, no restart policies) | `cyberlab check`, `run` |
| While running | every network of the project is `Internal` with `inhibit_ipv4`, every network a container joins is internal, no container publishes ports, is privileged or uses the host network; fails if no container or network is found | `run` |
| After stop | no container or network of the project is left | `run` |
| Checks and crafting | tools container with `--network none`, `--cap-drop ALL`, `no-new-privileges`, your uid | every command |

## Why `inhibit_ipv4`

`internal: true` removes the route out, but on a Linux host the bridge still carries a host address (the gateway, `x.x.x.1`), and every host service listening on all interfaces answers there. Tested on an Ubuntu 24.04 host: from a lab with `internal: true` alone, SSH (22) and 9 other host services accepted connections. With `com.docker.network.bridge.inhibit_ipv4: "true"` the bridge has no IPv4 address and all of them, plus public IPs and DNS, were unreachable, while lab services still reached each other. The policy and the runtime check both require it.

## Why fake-WAN subnets are TEST-NET only

Docker's rule for an internal network drops traffic from the lab bridge to addresses **outside** the lab subnet. A packet to an address **inside** the subnet that no container holds is not dropped by that rule: a container with `NET_RAW` or `NET_ADMIN` (Docker grants `NET_RAW` by default) can address it to the bridge's MAC, and the host may route it out of its own uplink. Tested on macOS Docker Desktop: for an internal, `inhibit_ipv4` lab on a public `/24`, the Docker VM's route lookup for an unheld address of that `/24` went out of `eth0`, and its `FORWARD` policy was `ACCEPT`. With a private subnet such a packet reaches only private addresses; with a public one it could reach the real hosts behind an IoC address. The policy therefore allows a custom subnet only inside the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), which are not routed on the internet. Not tested: whether a Linux host with Docker's default `FORWARD` policy (`DROP`) forwards such a packet at all.

## What it does not enforce

- **Docker is not a VM boundary.** A kernel or runtime escape from a lab container bypasses the network policy. For payloads you do not trust, run cyberlab inside a disposable VM, or with a hardened runtime (`cyberlab doctor` reports gVisor `runsc` or Kata when the engine has them).
- **Payload content.** The policy cannot tell a harmless string from a working exploit. The rules below are the agent's responsibility.
- **Image contents.** Third-party images are trusted as pulled; pin tags or digests, and the provenance records the image IDs used.

## Rules for payloads

1. Lab hosts only. Never point a generator at an external address; the internal network should make it fail, and that failure is a finding, not something to work around. A TEST-NET address a lab service holds on a fake-WAN subnet is a lab host; a real IoC address never is.
2. Detection strings, not weapons: strip reverse shells, persistence, credential theft, exfiltration and destructive actions from any proof of concept. The trace needs the bytes a detector sees, not a working compromise. Diagrams in `mechanism.md` name the marker; they never carry a payload.
3. Host names inside payloads use the `.invalid` top-level domain (RFC 2606), which never resolves.
4. Malware samples and captures of real incidents are data: never execute what they contain.
5. Cleartext protocols only (the capture must show the attack); no real credentials or personal data in any trace.

## Stopping everything

`cyberlab status` lists lab containers, networks, volumes and the images built for labs; `cyberlab down <lab>` stops one (`--images` also removes the images built for it); `cyberlab nuke` removes every `cyberlab-*` container, network and volume (`--images`: and every image built for a cyberlab lab). Pulled images and the tools image are never removed. The skill asks before any image removal and before `nuke`.
