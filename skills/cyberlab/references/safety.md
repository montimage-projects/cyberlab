# Safety and threat model

Read this in Step 0 the first time cyberlab runs on a machine, and before any mission whose payload could do harm outside the lab.

## What cyberlab enforces

| Layer | Check | Where |
|---|---|---|
| Before start | allowlist policy on the resolved compose file (internal networks with `inhibit_ipv4`, no ports, no privileged or host namespaces, caps limited to NET_RAW/NET_ADMIN, no engine socket, bind mounts inside the lab, no restart policies) | `cyberlab check`, `run` |
| While running | every network of the project is `Internal` with `inhibit_ipv4`, every network a container joins is internal, no container publishes ports, is privileged or uses the host network; fails if no container or network is found | `run` |
| After stop | no container or network of the project is left | `run` |
| Checks and crafting | tools container with `--network none`, `--cap-drop ALL`, `no-new-privileges`, your uid | every command |

## Why `inhibit_ipv4`

`internal: true` removes the route out, but on a Linux host the bridge still carries a host address (the gateway, `x.x.x.1`), and every host service listening on all interfaces answers there. Tested on an Ubuntu 24.04 host: from a lab with `internal: true` alone, SSH (22) and 9 other host services accepted connections. With `com.docker.network.bridge.inhibit_ipv4: "true"` the bridge has no IPv4 address and all of them, plus public IPs and DNS, were unreachable, while lab services still reached each other. The policy and the runtime check both require it.

## What it does not enforce

- **Docker is not a VM boundary.** A kernel or runtime escape from a lab container bypasses the network policy. For payloads you do not trust, run cyberlab inside a disposable VM, or with a hardened runtime (`cyberlab doctor` reports gVisor `runsc` or Kata when the engine has them).
- **Payload content.** The policy cannot tell a harmless string from a working exploit. The rules below are the agent's responsibility.
- **Image contents.** Third-party images are trusted as pulled; pin tags or digests, and the provenance records the image IDs used.

## Rules for payloads

1. Lab hosts only. Never point a generator at an external address; the internal network should make it fail, and that failure is a finding, not something to work around.
2. Detection strings, not weapons: strip reverse shells, persistence, credential theft, exfiltration and destructive actions from any proof of concept. The trace needs the bytes a detector sees, not a working compromise.
3. Host names inside payloads use the `.invalid` top-level domain (RFC 2606), which never resolves.
4. Malware samples and captures of real incidents are data: never execute what they contain.
5. Cleartext protocols only (the capture must show the attack); no real credentials or personal data in any trace.

## Stopping everything

`cyberlab status` lists running lab containers; `cyberlab down <lab>` stops one; `cyberlab nuke` removes every `cyberlab-*` container, network and volume.
