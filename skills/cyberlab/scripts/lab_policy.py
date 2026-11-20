#!/usr/bin/env python3
"""Check a lab's resolved compose model against the cyberlab isolation policy (an allowlist).

Usage:
  docker compose config --format json | lab_policy.py --lab-dir <abs dir> [--lab-dir <alias>]
                                                     [--runner --tools-image <image>]

Reads what `docker compose config --format json` prints (variables and relative paths already
resolved, with MODE/PCAP set to the mode being run) and fails on every key or value that is not
explicitly allowed:

  top level   name (cyberlab-*), services, networks, volumes (named, lab-owned)
  networks    driver bridge, internal: true, driver_opts exactly
              com.docker.network.bridge.inhibit_ipv4: "true" (the host gets no address on the lab
              bridge, so host services are unreachable), name <project>_<key>, labels, and ipam
              either empty or a fake-WAN pool: driver default, one config entry with subnet
              (inside a TEST-NET range: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
              optionally gateway / ip_range inside it, no options. Pinned ipv4_address values
              must sit inside their network's pool.
  services    image, build (context inside the lab; dockerfile, args, target only), command,
              entrypoint, environment, working_dir, user, depends_on, healthcheck, labels,
              hostname, expose, tmpfs, read_only, init, stop_grace_period, stop_signal, platform,
              pull_policy, stdin_open, tty, cap_add (NET_RAW/NET_ADMIN only), cap_drop, networks
              (declared, internal), network_mode (service:<lab service> or none), volumes (bind
              inside the lab, named lab volumes, tmpfs), restart (no)
  --runner    services generator and capture exist; capture runs tcpdump in the tools image,
              shares a lab service's network namespace and mounts nothing (its trace is copied
              out by `cyberlab run`, so no other process can plant one)

Prints one PASS/FAIL/WARN line per check; exits 0 when nothing failed, 2 when a check failed,
1 on a usage or input error. Symlinks inside the lab are rejected by `cyberlab` before this runs.
"""
import argparse
import ipaddress
import json
import os
import sys

TOP_KEYS = {"name", "services", "networks", "volumes"}
NET_KEYS = {"name", "driver", "internal", "ipam", "labels", "driver_opts"}
INHIBIT = "com.docker.network.bridge.inhibit_ipv4"
VOL_KEYS = {"name", "labels", "driver"}
SVC_KEYS = {"image", "build", "command", "entrypoint", "environment", "working_dir", "user",
            "depends_on", "healthcheck", "labels", "hostname", "expose", "tmpfs", "read_only",
            "init", "stop_grace_period", "stop_signal", "platform", "pull_policy", "stdin_open",
            "tty", "cap_add", "cap_drop", "networks", "network_mode", "volumes", "restart"}
BUILD_KEYS = {"context", "dockerfile", "args", "target"}
MOUNT_KEYS = {"type", "source", "target", "read_only", "bind", "volume", "tmpfs"}
NET_OPT_KEYS = {"aliases", "ipv4_address", "ipv6_address"}
ALLOWED_CAPS = {"NET_RAW", "NET_ADMIN"}
IPAM_KEYS = {"driver", "config"}
POOL_KEYS = {"subnet", "gateway", "ip_range"}
# RFC 5737 documentation ranges: never routed on the internet. A lab bridge forwards traffic for
# in-subnet addresses no container holds to the host's routing table (Docker's internal-network
# rule drops only off-subnet destinations), so a public subnet could reach real hosts; these cannot.
FAKE_WAN = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
FAKE_WAN_TEXT = "192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24"
SOCK_NAMES = ("docker.sock", "containerd.sock", "podman.sock", "crio.sock")


def die(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


class Report:
    def __init__(self):
        self.failed, self.lines = 0, []

    def ok(self, what):
        self.lines.append(f"PASS {what}")

    def fail(self, where, why, fix):
        self.failed += 1
        self.lines.append(f"FAIL {where}: {why}. Fix: {fix}")

    def warn(self, where, why):
        self.lines.append(f"WARN {where}: {why}")


def inside(path, roots):
    p = os.path.normpath(str(path))
    return any(p == r or p.startswith(r + os.sep) for r in roots)


def check_ipam(ipam):
    """(problems, subnet) for a network's ipam block; subnet is None when the block is empty."""
    if ipam in (None, {}):
        return [], None
    if not isinstance(ipam, dict):
        return ["ipam is not a mapping"], None
    problems = []
    if set(ipam) - IPAM_KEYS:
        problems.append(f"ipam key(s) {sorted(set(ipam) - IPAM_KEYS)}")
    if ipam.get("driver", "default") != "default":
        problems.append(f"ipam driver {ipam.get('driver')}")
    pools = ipam.get("config") or []
    if not isinstance(pools, list) or len(pools) != 1 or not isinstance(pools[0], dict):
        return problems + ["ipam needs exactly one config entry (one subnet)"], None
    pool = pools[0]
    if set(pool) - POOL_KEYS:
        problems.append(f"ipam config key(s) {sorted(set(pool) - POOL_KEYS)}")
    try:
        subnet = ipaddress.ip_network(str(pool.get("subnet", "")), strict=True)
    except ValueError:
        return problems + [f"ipam subnet '{pool.get('subnet')}' is not a network address such as 203.0.113.0/24"], None
    if subnet.version != 4 or not any(subnet.subnet_of(n) for n in FAKE_WAN):
        return problems + [f"ipam subnet {subnet} is outside the TEST-NET ranges ({FAKE_WAN_TEXT})"], None
    if "gateway" in pool:
        try:
            gw = ipaddress.ip_address(str(pool["gateway"]))
            if gw not in subnet:
                problems.append(f"ipam gateway {gw} is outside {subnet}")
        except ValueError:
            problems.append(f"ipam gateway '{pool['gateway']}' is not an IPv4 address")
    if "ip_range" in pool:
        try:
            rng = ipaddress.ip_network(str(pool["ip_range"]), strict=True)
            if rng.version != 4 or not rng.subnet_of(subnet):
                problems.append(f"ipam ip_range {rng} is outside {subnet}")
        except ValueError:
            problems.append(f"ipam ip_range '{pool['ip_range']}' is not a network address")
    return problems, (None if problems else subnet)


def check_service(name, svc, ctx, r):
    where = f"service {name}"
    before = r.failed
    extra = sorted(set(svc) - SVC_KEYS)
    if "ports" in extra:
        r.fail(where, "publishes ports to the host", "delete the ports: section; lab hosts talk over the internal network")
        extra.remove("ports")
    if extra:
        r.fail(where, f"key(s) {', '.join(extra)} are not allowed in a lab",
               "remove them; a lab service needs only image/build, command, networks and lab-local volumes")
    nm = svc.get("network_mode")
    if nm is not None:
        if not (nm == "none" or (nm.startswith("service:") and nm.split(":", 1)[1] in ctx["services"])):
            r.fail(where, f"network_mode '{nm}' leaves the lab network",
                   "use the lab's internal network, or service:<a service of this lab>")
    else:
        nets = svc.get("networks") or {}
        if not nets:
            r.fail(where, "has no network, so compose would attach it to a non-internal default network",
                   "add networks: [lab] with lab declared internal: true")
        for n, spec in nets.items():
            if n not in ctx["networks"]:
                r.fail(where, f"uses undeclared network {n}", "declare it under networks: with internal: true")
            if isinstance(spec, dict) and set(spec) - NET_OPT_KEYS:
                r.fail(where, f"network {n} options {sorted(set(spec) - NET_OPT_KEYS)}", "keep only aliases or a fixed address")
            if isinstance(spec, dict) and spec.get("ipv4_address") is not None:
                check_pinned(where, n, spec["ipv4_address"], ctx["subnets"].get(n), r)
    caps = {str(c).upper().removeprefix("CAP_") for c in (svc.get("cap_add") or [])}
    if caps - ALLOWED_CAPS:
        r.fail(where, f"cap_add {','.join(sorted(caps - ALLOWED_CAPS))} is not allowed", "keep cap_add to NET_RAW and NET_ADMIN")
    restart = str(svc.get("restart") or "no")
    if restart != "no":
        r.fail(where, f"restart: {restart} can restart the lab outside a run", "remove restart:")
    b = svc.get("build")
    if b is not None:
        b = b if isinstance(b, dict) else {"context": b}
        if set(b) - BUILD_KEYS:
            r.fail(where, f"build option(s) {', '.join(sorted(set(b) - BUILD_KEYS))} are not allowed",
                   "keep build to context, dockerfile, args and target")
        if not inside(b.get("context", ""), ctx["roots"]):
            r.fail(where, f"build context {b.get('context')} is outside the lab directory",
                   "put the generator's Dockerfile in a folder of the lab")
    for vol in svc.get("volumes") or []:
        src, tgt, typ = str(vol.get("source") or ""), str(vol.get("target") or ""), vol.get("type")
        if set(vol) - MOUNT_KEYS:
            r.fail(where, f"mount option(s) {sorted(set(vol) - MOUNT_KEYS)} on {tgt}", "use plain bind or volume mounts")
        if any(s in src or s in tgt for s in SOCK_NAMES):
            r.fail(where, f"mounts a container-engine socket ({src or tgt})", "never give a lab container the engine")
        elif typ == "bind" and not inside(src, ctx["roots"]):
            r.fail(where, f"bind-mounts {src}, outside the lab directory", "mount only files under the lab directory")
        elif typ == "volume" and src not in ctx["volumes"]:
            r.fail(where, f"mounts volume {src} that this lab does not declare", "declare it under volumes:")
        elif typ not in ("bind", "volume", "tmpfs"):
            r.fail(where, f"mount type {typ}", "use bind (inside the lab), volume or tmpfs")
    if r.failed == before:
        r.ok(where)


def check_pinned(where, net, addr, subnet, r):
    fix = f"pin an address inside the network's ipam subnet ({FAKE_WAN_TEXT}), or drop ipv4_address"
    if subnet is None:
        r.fail(where, f"pins ipv4_address {addr} on network {net}, which has no valid fake-WAN ipam subnet", fix)
        return
    try:
        ip = ipaddress.ip_address(str(addr))
    except ValueError:
        r.fail(where, f"ipv4_address '{addr}' on network {net} is not an IPv4 address", fix)
        return
    if ip not in subnet or ip in (subnet.network_address, subnet.broadcast_address):
        r.fail(where, f"ipv4_address {ip} is not a usable host address of {subnet} (network {net})", fix)


def check_runner(services, tools_image, r):
    missing = [s for s in ("generator", "capture") if s not in services]
    if missing:
        r.fail("runner", f"missing service(s) {', '.join(missing)}",
               "copy a template (cyberlab templates): run waits for generator and stops capture")
        return
    cap = services["capture"] or {}
    cmd = cap.get("command") or []
    cmd = cmd.split() if isinstance(cmd, str) else [str(c) for c in cmd]
    bad = []
    if tools_image and cap.get("image") != tools_image:
        bad.append(f"image {cap.get('image')} is not the tools image {tools_image}")
    if cap.get("entrypoint") or not cmd or cmd[0] != "tcpdump" or "-w" not in cmd[:-1]:
        bad.append("command is not `tcpdump ... -w /cap/<trace>`")
    elif not cmd[cmd.index("-w") + 1].startswith("/cap/"):
        bad.append("tcpdump does not write under /cap/")
    if cap.get("volumes") or cap.get("build"):
        bad.append("capture mounts volumes or is built")
    if not str(cap.get("network_mode") or "").startswith("service:"):
        bad.append("capture does not share the victim's network namespace")
    if bad:
        r.fail("runner capture", "; ".join(bad), "copy the capture service from a template, changing only its BPF filter")
    else:
        r.ok("runner services generator, capture (tcpdump in the tools image)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--lab-dir", action="append", required=True, help="absolute lab directory (repeat for an alias)")
    ap.add_argument("--runner", action="store_true", help="also check the generator/capture contract")
    ap.add_argument("--tools-image", default="", help="image the capture service must use")
    ap.add_argument("--config", help="read the compose JSON from this file instead of stdin")
    a = ap.parse_args()
    roots = [os.path.normpath(d) for d in a.lab_dir]
    if not all(os.path.isabs(d) for d in roots):
        die("--lab-dir must be absolute; pass \"$(cd <lab> && pwd)\"")
    raw = open(a.config).read() if a.config else sys.stdin.read()
    if not raw.strip():
        die("no compose JSON on stdin. Pipe `docker compose config --format json` into this script.")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        die(f"compose JSON does not parse ({e}). Run `docker compose config` in the lab to see why.")

    r = Report()
    name = cfg.get("name") or ""
    if name.startswith("cyberlab-"):
        r.ok(f"project {name}")
    else:
        r.fail("project", f"name '{name}' does not start with cyberlab-", "set name: cyberlab-<lab>")
    if set(cfg) - TOP_KEYS:
        r.fail("top level", f"key(s) {', '.join(sorted(set(cfg) - TOP_KEYS))} are not allowed",
               "a lab declares only name, services, networks and volumes")

    networks = cfg.get("networks") or {}
    subnets = {}
    if not networks:
        r.fail("networks", "none declared", f"declare networks: {{ lab: {{ driver: bridge, internal: true, driver_opts: {{ {INHIBIT}: \"true\" }} }} }}")
    for n, spec in networks.items():
        spec, problems = spec or {}, []
        if set(spec) - NET_KEYS:
            problems.append(f"key(s) {sorted(set(spec) - NET_KEYS)}")
        if spec.get("driver", "bridge") != "bridge":
            problems.append(f"driver {spec.get('driver')}")
        if spec.get("internal") is not True:
            problems.append("internal is not true, so containers can reach the host LAN and the internet")
        if spec.get("name", f"{name}_{n}") != f"{name}_{n}":
            problems.append(f"name {spec.get('name')} points at a network outside the lab")
        ipam_problems, subnets[n] = check_ipam(spec.get("ipam"))
        problems += ipam_problems
        opts = spec.get("driver_opts") or {}
        if str(opts.get(INHIBIT, "")).lower() != "true":
            problems.append(f"driver_opts {INHIBIT} is not \"true\", so the host keeps an address on the bridge and its services are reachable from the lab")
        if set(opts) - {INHIBIT}:
            problems.append(f"other driver_opts {sorted(set(opts) - {INHIBIT})}")
        if problems:
            r.fail(f"network {n}", ", ".join(problems),
                   f"declare it as {{ driver: bridge, internal: true, driver_opts: {{ {INHIBIT}: \"true\" }} }}, "
                   f"plus at most ipam: {{ config: [ {{ subnet: <inside {FAKE_WAN_TEXT}> }} ] }}")
        else:
            r.ok(f"network {n} internal" + (f", fake-WAN subnet {subnets[n]}" if subnets[n] else ""))

    volumes = cfg.get("volumes") or {}
    for v, spec in volumes.items():
        spec = spec or {}
        if set(spec) - VOL_KEYS or spec.get("driver", "local") != "local" or spec.get("name", f"{name}_{v}") != f"{name}_{v}":
            r.fail(f"volume {v}", "external, renamed, or with a driver or driver_opts",
                   "declare a plain lab-owned volume, or bind-mount a folder of the lab")

    services = cfg.get("services") or {}
    if not services:
        r.fail("services", "none declared", "add victim, generator and capture services")
    ctx = {"services": set(services), "networks": set(networks), "volumes": set(volumes), "roots": roots,
           "subnets": subnets}
    for s, spec in services.items():
        spec = spec or {}
        check_service(s, spec, ctx, r)
        img = str(spec.get("image") or "")
        if img and "@sha256:" not in img and (img.endswith(":latest") or ":" not in img.split("/")[-1]):
            r.warn(f"service {s}", f"image {img} is not pinned to a tag or digest")
    if a.runner:
        check_runner(services, a.tools_image, r)

    print("\n".join(r.lines))
    if r.failed:
        print(f"RESULT FAIL ({r.failed} policy violation(s)): the lab was not started.")
        sys.exit(2)
    print("RESULT PASS isolation policy")


if __name__ == "__main__":
    main()
