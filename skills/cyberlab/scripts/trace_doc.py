#!/usr/bin/env python3
"""Provenance and reproduction document of each trace. Runs INSIDE the tools image (`cyberlab`).

Usage:
  trace_doc.py lab-files --lab <dir>
      JSON on stdout: {"inputs": {path: sha256}, "froms": [base image refs of the lab's Dockerfiles]}.
      Inputs are every lab file except out/ and the documentation (mission.md, mechanism.md, expect.json).
  trace_doc.py provenance --lab <dir> --trace <name.pcap> --origin <o> --generator <g>
                          --command <cmd> --version <cyberlab version> [--tools-image <ref>]
      Reads a JSON context on stdin (run facts gathered by `cyberlab` on the host: resolved compose,
      `docker image inspect` objects, docker version, env, project...), writes
      <dir>/out/<name>.provenance.json and prints "<frames> <sha256>".
  trace_doc.py doc --lab <dir> [--trace <name.pcap>]...
      Writes <dir>/out/<name>.md for each trace (default: every out/*.pcap): who is who (the
      attacker or client, the victim or server and every other address, with Mermaid diagrams),
      what the trace contains, how the attack (or protocol) works, how it was generated, what was
      checked, and how to reproduce it. Built from mission.md, mechanism.md,
      expect.json, out/verify.json, out/<name>.provenance.json and tshark summaries of the trace.

Only the Python standard library, capinfos and tshark are used. Exit: 0 ok, 1 usage or input error.
"""
import argparse
import collections
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys

SKIP_DIRS = {"out", "__pycache__", ".git"}
SKIP_FILES = {"mission.md", "mechanism.md", "expect.json", ".DS_Store"}
PACKET_ROWS = 40
CONV_ROWS = 25
LOG_TAIL = 15
PHS_ROWS = 30
PHS_DEPTH = 7
LINE_MAX = 200
SEQ_ROWS = 30      # messages in the exchange diagram
SEQ_TEXT = 70      # characters of a message label
NODE_MAX = 6       # addresses drawn in the who-is-who diagram
ROLE_ROWS = 12     # addresses listed in the who-is-who table
TIME_BINS = 30     # bars in the traffic-over-time chart
PIE_SLICES = 7
TIME_STEPS = (0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600)


def script_reads(lab, command, generator):
    """Trace names a --script craft's source mentions (e.g. derive.py opening out/benign.pcap)."""
    m = re.search(r"--script (\S+)", command or "") or re.match(r"python3 (\S+)", generator or "")
    if not m:
        return None
    try:
        text = open(os.path.join(lab, m.group(1).strip("'")), errors="replace").read()
    except OSError:
        return None
    return {n for n in os.listdir(os.path.join(lab, "out")) if n.endswith(".pcap") and n in text}


def write_atomic(path, text):
    """Write through a temporary file and rename it: a bind mount can report a file just deleted on the
    host as missing when it is reopened for writing (seen on Docker Desktop)."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def die(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def lab_inputs(lab):
    """{relative path: sha256} of the files that define the lab (everything but out/ and the brief)."""
    files = {}
    for root, dirs, names in os.walk(lab):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (root == lab and d.startswith(".")))
        for n in sorted(names):
            rel = os.path.relpath(os.path.join(root, n), lab)
            if rel in SKIP_FILES or n == ".DS_Store" or n.endswith(".pyc"):
                continue
            p = os.path.join(root, n)
            if os.path.isfile(p) and not os.path.islink(p):
                files[rel] = sha256(p)
    return files


def dockerfile_froms(lab):
    refs = []
    for root, dirs, names in os.walk(lab):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            if not n.startswith("Dockerfile"):
                continue
            stages = set()
            for line in open(os.path.join(root, n), errors="replace"):
                m = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
                if m:
                    ref = m.group(1)
                    if ref.lower() not in stages and "$" not in ref and ref not in refs and ref != "scratch":
                        refs.append(ref)
                    if m.group(2):
                        stages.add(m.group(2).lower())
    return refs


def tool_versions():
    out = []
    for cmd in (["tshark", "--version"], ["tcpdump", "--version"], ["python3", "--version"]):
        rc, so, se = run(cmd)
        line = (so or se).strip().splitlines()
        if line:
            out.append(line[0].rstrip("."))
    return "; ".join(out)


def capinfo(path):
    rc, out, err = run(["capinfos", "-M", path])
    info = {}
    if rc == 0:
        for line in out.splitlines():
            if ":" in line and not line.startswith(" "):
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
    return info


def image_summary(obj):
    return {
        "id": obj.get("Id", ""),
        "tags": obj.get("RepoTags") or [],
        "repo_digests": obj.get("RepoDigests") or [],
        "platform": "/".join(x for x in (obj.get("Os"), obj.get("Architecture"), obj.get("Variant")) if x),
        "created": obj.get("Created", ""),
    }


# --------------------------------------------------------------------------- provenance

def cmd_provenance(a):
    try:
        ctx = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        die(f"provenance context on stdin is not JSON ({e}).")
    path = os.path.join(a.lab, "out", a.trace)
    if not os.path.isfile(path):
        die(f"{path} not found.")
    info = capinfo(path)
    frames = int(info.get("Number of packets", "0") or 0)
    digest = sha256(path)
    inspect = {o.get("Id"): o for o in ctx.pop("inspect", []) if isinstance(o, dict)}
    by_ref = {}
    for o in inspect.values():
        for t in (o.get("RepoTags") or []) + (o.get("RepoDigests") or []):
            by_ref[t] = o

    prov = {"trace": a.trace, "origin": a.origin, "generator": a.generator, "lab": os.path.basename(ctx.pop("lab_name", "") or a.lab.rstrip("/")),
            "created_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "frames": frames, "sha256": digest}
    for k in ("project", "generator_exit", "dropped", "images", "addresses"):
        if k in ctx:
            prov[k] = ctx.pop(k)
    prov["cyberlab_version"] = a.version
    prov["command"] = a.command
    if ctx.get("env"):
        prov["env"] = ctx.pop("env")
    prov["inputs"] = lab_inputs(a.lab)
    prov["inputs_recorded"] = "at generation"

    compose = ctx.pop("compose", None)
    if isinstance(compose, dict):
        services = {}
        for name, s in sorted((compose.get("services") or {}).items()):
            entry = {}
            if s.get("image"):
                entry["image"] = s["image"]
            if isinstance(s.get("build"), dict):
                b = s["build"]
                ctxdir = b.get("context", "")
                entry["build"] = os.path.relpath(ctxdir, ctx.get("lab_host_dir", ctxdir)) if ctx.get("lab_host_dir") else ctxdir
                if b.get("dockerfile") and b["dockerfile"] != "Dockerfile":
                    entry["dockerfile"] = b["dockerfile"]
            for k in ("entrypoint", "command", "network_mode", "environment"):
                if s.get(k):
                    entry[k] = s[k]
            services[name] = entry
        prov["services"] = services
    ids = ctx.pop("image_ids", [])
    details = []
    for i in ids:
        o = inspect.get(i) or next((v for k, v in inspect.items() if k and k.startswith(i)), None)
        if o:
            details.append(image_summary(o))
    if details:
        prov["image_details"] = details
    bases = []
    for ref in dockerfile_froms(a.lab):
        name, _, pin = ref.partition("@")
        o = (by_ref.get(ref) or (pin and by_ref.get(name.rsplit(":", 1)[0] + "@" + pin))
             or by_ref.get(name) or by_ref.get(name + ":latest"))
        bases.append({"ref": ref, **(image_summary(o) if o else {"id": "", "repo_digests": []})})
    if bases:
        prov["base_images"] = bases
    tools_id = ctx.pop("tools_id", "")
    prov["tools"] = {"image": a.tools_image, "id": tools_id, "versions": tool_versions()}
    if ctx.get("host"):
        prov["host"] = ctx.pop("host")
    if a.origin.startswith("crafted") and a.generator.startswith("python3 "):
        others = {}
        reads = script_reads(a.lab, a.command, a.generator) or set()
        for n in sorted(os.listdir(os.path.join(a.lab, "out"))):
            if n.endswith(".pcap") and n != a.trace and n in reads:
                others[n] = sha256(os.path.join(a.lab, "out", n))
        if others:
            prov["lab_traces_at_generation"] = others
    write_atomic(os.path.join(a.lab, "out", a.trace[:-5] + ".provenance.json"),
                 json.dumps(prov, indent=1, ensure_ascii=False) + "\n")
    print(f"{frames} {digest}")


# --------------------------------------------------------------------------- document

def read_mission(lab):
    m = {"goal": "", "fields": {}, "traces": {}, "log": []}
    p = os.path.join(lab, "mission.md")
    if not os.path.isfile(p):
        return m
    in_log = False
    for line in open(p, errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("# Mission:"):
            m["goal"] = line.split(":", 1)[1].strip()
        elif re.match(r"##\s+Log", line):
            in_log = True
        elif in_log and line.startswith("- "):
            m["log"].append(line[2:].strip())
        else:
            mm = re.match(r"-\s+([A-Za-z/ ]+):\s*(.*)", line)
            if mm and not in_log:
                key, val = mm.group(1).strip(), mm.group(2).strip()
                if key == "Traces":
                    t = re.match(r"`?([\w.\-]+\.pcap)`?\s*(?:—|–|-|:)?\s*(.*)", val)
                    if t:
                        m["traces"][t.group(1)] = t.group(2).strip()
                else:
                    m["fields"].setdefault(key, val)
    return m


def read_mechanism(lab):
    """mechanism.md split into its title, general text, per-trace sections and references.
    Lines inside code fences (a Mermaid diagram) are never headings. A trace section may open with
    `Roles: <role> = <lab service or address>, ...`, which names who is who in that trace."""
    m = {"title": "", "body": [], "traces": {}, "refs": [], "roles": {}, "diagrams": {}, "blocks": [], "found": False}
    p = os.path.join(lab, "mechanism.md")
    if not os.path.isfile(p):
        return m
    m["found"] = True
    cur, key, fence, block = m["body"], "", None, None
    for line in open(p, errors="replace"):
        line = line.rstrip("\n")
        f = re.match(r"\s*(`{3,}|~{3,})\s*(\S*)", line)
        if fence:
            if f and f.group(1)[0] == fence[0] and len(f.group(1)) >= len(fence) and not f.group(2):
                fence, block = None, None
            elif block is not None:
                block.append(line)
            cur.append(line)
            continue
        if f:
            fence = f.group(1)
            if f.group(2).lower() == "mermaid":
                m["diagrams"][key] = m["diagrams"].get(key, 0) + 1
                block = []
                m["blocks"].append((key, block))
            cur.append(line)
            continue
        h1 = re.match(r"#\s+(?:Mechanism:\s*)?(.*)", line)
        h2 = re.match(r"##\s+(.*)", line)
        if h1 and not line.startswith("##"):
            m["title"] = h1.group(1).strip()
        elif h2:
            name = h2.group(1).strip().strip("`")
            key = "#refs" if name.lower() in ("references", "sources") else name
            cur = m["refs"] if key == "#refs" else m["traces"].setdefault(name, [])
        elif key not in ("", "#refs") and not any(x.strip() for x in cur) and re.match(r"Roles:\s*\S", line):
            m["roles"][key] = parse_roles(line.split(":", 1)[1])
        else:
            cur.append(re.sub(r"^(#{3,})", r"#\1", line))   # keep deeper headings below the doc's own
    if fence and block is not None:
        m["blocks"][-1] = (m["blocks"][-1][0], None)   # a diagram whose fence never closes
    for k in ("body", "refs"):
        m[k] = "\n".join(m[k]).strip()
    m["traces"] = {k: "\n".join(v).strip() for k, v in m["traces"].items()}
    return m


MM_OPEN = re.compile(r"\s*(loop|alt|opt|par|critical|break|rect|box)\b")
FLOW_BAD = re.compile(r'\w\[(?![("\[/\\])[^\]"]*[()][^\]"]*\]')


def mermaid_lint(lines):
    """The mistakes that stop a Mermaid diagram from rendering, seen most: a ';' in a sequence message
    (Mermaid reads it as the end of the statement), a block without its 'end', an unquoted flowchart
    label holding brackets or parentheses, an unclosed fence. Not a parser: a clean result is no proof."""
    if lines is None:
        return ["the ```mermaid block has no closing fence"]
    lines = [l for l in lines if not l.strip().startswith("%%")]   # comments
    kind = next((l.split()[0] for l in lines if l.strip()), "")
    issues = []
    if kind == "sequenceDiagram":
        opened = sum(1 for l in lines if MM_OPEN.match(l))
        ends = sum(1 for l in lines if l.strip() == "end")
        if opened != ends:
            issues.append(f"{opened} loop/alt/opt/par/critical/break/rect/box block(s) but {ends} `end` line(s)")
        if any(";" in re.sub(r"#\w+;", "", l) for l in lines):
            issues.append("a `;` in a sequenceDiagram line ends the statement: write `#59;` or rephrase")
    elif kind in ("flowchart", "graph"):
        if any(FLOW_BAD.search(l) for l in lines):
            issues.append("a flowchart label holding parentheses must be quoted: `a[\"text (note)\"]`")
    elif not kind:
        issues.append("an empty ```mermaid block")
    return issues


def parse_roles(text):
    """'attacker = generator, victim = 10.0.0.2' -> [("Attacker", "generator"), ("Victim", "10.0.0.2")]."""
    out = []
    for part in re.split(r"[,;]", text):
        role, sep, target = part.partition("=")
        role, target = role.strip(" `*"), target.strip(" `*.")
        if sep and role and target:
            out.append((role[:1].upper() + role[1:], target))
    return out


def legacy_command(prov, lab_name, trace):
    """Reconstruct the command of a trace generated before provenance recorded it."""
    g = prov.get("generator", "")
    mode = re.match(r".* mode (\S+)$", g)
    if mode:
        return f"cyberlab run <lab> {mode.group(1)}"
    if g.startswith("craft_pcap.py "):
        return f"cyberlab craft <lab> {trace} -- {g[len('craft_pcap.py '):]}"
    s = re.match(r"python3 (\S+)\s*(.*)", g)
    if s:
        rest = f" -- {s.group(2)}" if s.group(2) else ""
        return f"cyberlab craft <lab> {trace} --script {s.group(1)}{rest}"
    return ""


def md_cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def block(text, lang="text"):
    return f"```{lang}\n{text.rstrip()}\n```"


def collapse_phs(lines):
    """Protocol hierarchy to PHS_DEPTH levels, without a layer repeated inside itself (HTTP/2 nests
    one per frame) or tshark's truncated '...' lines, capped at PHS_ROWS lines."""
    kept, stack, cut = [], [], 0
    for l in lines:
        depth = len(l) - len(l.lstrip(" "))
        name = l.split()[0] if l.split() else ""
        while stack and stack[-1][0] >= depth:
            stack.pop()
        parent = stack[-1][1] if stack else None
        stack.append((depth, name))
        if name.startswith("...") or depth > 2 * (PHS_DEPTH - 1):
            cut += 1
        elif name != parent:
            kept.append(l)
    note = f"(+{len(kept) - PHS_ROWS} more lines)" if len(kept) > PHS_ROWS else ""
    if cut:
        note = (note + " " if note else "") + f"(deeper layers omitted)"
    return "\n".join(kept[:PHS_ROWS]) + (f"\n{note}" if note else "")


def trace_summaries(path):
    out = {}
    rc, so, _ = run(["tshark", "-n", "-r", path, "-qz", "io,phs"])
    if rc == 0:
        lines = [l for l in so.splitlines() if l.strip() and not l.startswith("=")]
        out["phs"] = collapse_phs([l for l in lines if not l.startswith(("Protocol Hierarchy", "Filter:"))])
    for kind in ("ip", "ipv6", "eth"):
        rc, so, _ = run(["tshark", "-n", "-r", path, "-qz", f"conv,{kind}"])
        rows = [l for l in so.splitlines() if "<->" in l] if rc == 0 else []
        if rows:
            head = [l for l in so.splitlines() if l.strip().startswith("|")][:2]
            more = f"\n… {len(rows) - CONV_ROWS} more conversation(s)" if len(rows) > CONV_ROWS else ""
            out["conv"] = (kind, "\n".join(head + rows[:CONV_ROWS]) + more, len(rows))
            break
    rc, so, _ = run(["tshark", "-n", "-r", path, "-c", str(PACKET_ROWS)])
    if rc == 0:
        out["packets"] = "\n".join(l if len(l) <= LINE_MAX else l[:LINE_MAX] + " …" for l in so.rstrip().splitlines())
    return out


# --------------------------------------------------------------------------- who is who, diagrams

FRAME_FIELDS = ("frame.number", "frame.time_relative", "frame.len", "eth.src", "eth.dst", "ip.src", "ip.dst",
                "ipv6.src", "ipv6.dst", "tcp.flags", "tcp.len", "_ws.col.Protocol", "_ws.col.Info")
MM_ESC = {"#": "#35;", ";": "#59;", "<": "#lt;", ">": "#gt;", "%": "#37;", '"': "#quot;", "&": "#amp;",
          "`": "#96;", "{": "#123;", "}": "#125;", "|": "#124;"}
TCP_NOISE = re.compile(r"\s*\b(?:Seq|Ack|Win|Len|MSS|TSval|TSecr|WS|SLE|SRE)=\S+|\s*\bSACK_PERM\b(?:=\S+)?"
                       r"|\s*\[TCP segment of a reassembled PDU\]")


def frame_rows(path):
    """One row per frame: number, time, length, source and destination (outer IP or IPv6 address, else
    MAC), TCP flags and payload length, protocol and info columns."""
    cmd = ["tshark", "-n", "-r", path, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f", "-E", "quote=n"]
    for f in FRAME_FIELDS:
        cmd += ["-e", f]
    rc, so, _ = run(cmd)
    rows = []
    if rc != 0:
        return rows
    mac_ip = {}
    for line in so.splitlines():
        v = line.split("\t")
        v = (v + [""] * len(FRAME_FIELDS))[:len(FRAME_FIELDS) - 1] + ["\t".join(v[len(FRAME_FIELDS) - 1:])]
        num, t, ln, esrc, edst, s4, d4, s6, d6, flags, tlen, proto, info = v
        src, dst = s4 or s6, d4 or d6
        if src and esrc:
            mac_ip.setdefault(esrc, src)
        try:
            rows.append({"num": int(num), "t": float(t or 0), "len": int(ln or 0), "esrc": esrc, "edst": edst,
                         "src": src, "dst": dst, "flags": int(flags, 16) if flags else -1,
                         "tlen": int(tlen) if tlen else -1, "proto": proto.strip(), "info": info.strip()})
        except ValueError:
            continue
    for r in rows:   # a frame with no IP header (ARP) belongs to the host whose MAC sent IP frames
        r["src"] = r["src"] or mac_ip.get(r["esrc"], r["esrc"])
        r["dst"] = r["dst"] or mac_ip.get(r["edst"], r["edst"])
    return rows


def addr_kind(a):
    """'mac', 'ip' or '' (not an address, e.g. Docker's "invalid IP")."""
    if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", a or "", re.I):
        return "mac"
    try:
        ipaddress.ip_address(a)
        return "ip"
    except ValueError:
        return ""


def addr_note(a):
    """What an address that is no host means: broadcast, multicast, unspecified; else ''."""
    if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", a or "", re.I):
        return "broadcast" if a.lower() == "ff:ff:ff:ff:ff:ff" else ("multicast" if int(a[:2], 16) & 1 else "")
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return ""
    if a == "255.255.255.255":
        return "broadcast"
    return "multicast" if ip.is_multicast else ("unspecified (no address yet)" if ip.is_unspecified else "")


def trace_kind(trace, desc):
    """attack | benign | other, from the trace name, else the verdict in its Traces: line."""
    n = trace.lower()
    if n.startswith("attack"):
        return "attack"
    if n.startswith("benign"):
        return "benign"
    if re.search(r"\bfires\b", desc or "", re.I):
        return "attack"
    return "benign" if re.search(r"\bstays?\s+silent\b", desc or "", re.I) else "other"


def craft_addresses():
    """The fixed client and server addresses craft_pcap.py writes (it sits next to this script)."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import craft_pcap as c
        mac = lambda b: ":".join(f"{x:02x}" for x in b)
        return ({str(ipaddress.ip_address(c.CLIENT_IP4)), str(ipaddress.ip_address(c.CLIENT_IP6)), mac(c.CLIENT_MAC)},
                {str(ipaddress.ip_address(c.SERVER_IP4)), str(ipaddress.ip_address(c.SERVER_IP6)), mac(c.SERVER_MAC)})
    except Exception:   # an older or missing craft_pcap.py: fall back to inferring the roles
        return set(), set()


def derived_sources(prov, lab=""):
    """The lab traces a --script craft read (recorded at generation), each with what it is when its own
    provenance says so: [(name, "a lab capture" | "a crafted trace" | "")]. As in doc_warnings, a trace the
    script does not name (recorded by an older cyberlab that listed every trace in out/) is no source."""
    reads = script_reads(lab, prov.get("command"), prov.get("generator")) if lab else None
    out = []
    for n in sorted(prov.get("lab_traces_at_generation") or {}):
        if reads is not None and n not in reads:
            continue
        origin = ""
        if lab:
            try:
                with open(os.path.join(lab, "out", n[:-5] + ".provenance.json")) as f:
                    origin = json.load(f).get("origin", "")
            except (OSError, ValueError, AttributeError):
                origin = ""
        out.append((n, "a lab capture" if origin == "lab capture" else ("a crafted trace" if str(origin).startswith("crafted") else "")))
    return out


def who_is_who(trace, prov, mech, mission, rows, lab=""):
    """Who sent the trace's frames: one entry per address, the primary roles first.
    Sources, strongest last: the trace (inferred), craft_pcap.py's fixed addresses (crafted), the
    addresses `cyberlab run` recorded from Docker (recorded), a Roles: line in mechanism.md (declared).
    `lab` lets a derived trace say what its source traces are."""
    name = trace[:-5]
    desc = mission["traces"].get(trace, "")
    kind = trace_kind(trace, desc)
    gen_role, vic_role = ("Attacker", "Victim") if kind == "attack" else ("Client", "Server")
    origin = prov.get("origin", "")
    crafted = origin.startswith("crafted")
    derived = derived_sources(prov, lab) if crafted else []
    gen = prov.get("generator", "").split()
    script = gen[1] if len(gen) > 1 and gen[0] == "python3" else "the script"
    stats = collections.OrderedDict()
    pairs = collections.Counter()
    mac_of = {}
    mac_ips = collections.defaultdict(set)   # MAC -> the addresses it sent IP frames from, and back
    ip_macs = collections.defaultdict(set)
    for r in rows:
        for a, side in ((r["src"], "sent"), (r["dst"], "recv")):
            if a:
                s = stats.setdefault(a, {"sent": 0, "recv": 0, "bytes": 0})
                s[side] += 1
        if r["src"]:
            stats[r["src"]]["bytes"] += r["len"]
            if r["esrc"] and r["esrc"] != r["src"]:
                mac_of.setdefault(r["src"], r["esrc"])
                if addr_kind(r["src"]) == "ip" and not addr_note(r["src"]):
                    mac_ips[r["esrc"].lower()].add(r["src"])
                    ip_macs[r["src"]].add(r["esrc"].lower())
        if r["src"] and r["dst"]:
            pairs[(r["src"], r["dst"])] += 1
    role = {}       # address -> {"role", "service", "how"}
    services = prov.get("services") or {}
    svc_addr = {}
    for svc, a in (prov.get("addresses") or {}).items():
        keys = [x for x in (a.get("ipv4"), a.get("ipv6"), a.get("mac")) if x and (addr_kind(x))]
        svc_addr[svc] = keys
        label = gen_role if svc == "generator" else (vic_role if svc == "victim" else f"Lab host `{svc}`")
        for k in keys:
            if k in stats:
                role[k] = {"role": label, "service": svc, "how": "recorded"}
    if crafted and not role and prov.get("generator", "").startswith("craft_pcap.py"):
        cli, srv = craft_addresses()
        for k in stats:
            if k in cli or k in srv:
                role[k] = {"role": gen_role if k in cli else vic_role, "service": "", "how": "crafted"}
    unresolved = []
    for rname, target in mech.get("roles", {}).get(trace) or mech.get("roles", {}).get(name) or []:
        keys = [k for k in svc_addr.get(target, []) if k in stats] or ([target] if target in stats else [])
        low = target.lower()
        if not keys:
            keys = [k for k in stats if k.lower() == low]
        why = ""
        if not keys and addr_kind(target) == "mac" and mac_ips.get(low):
            # a MAC that sent IP frames is folded into its IP address: take that address when it is the
            # host's only one (one IPv4, one IPv6) and no other MAC sent it, never guess in a spoofed trace
            ips = sorted(mac_ips[low], key=lambda x: (ipaddress.ip_address(x).version, ipaddress.ip_address(x)))
            versions = [ipaddress.ip_address(x).version for x in ips]
            shared = sorted({m for x in ips for m in ip_macs[x]} - {low})
            if len(versions) != len(set(versions)):
                why = f"MAC {target} sent IP frames from several addresses ({', '.join(ips)})"
            elif shared:
                why = (f"{', '.join(ips)}, the address{'es' if len(ips) > 1 else ''} MAC {target} sent from, "
                       f"also came from MAC {', '.join(shared)}")
            else:
                keys = [x for x in ips if x in stats]
        if not keys:
            unresolved.append((rname, target, why))
        for k in keys:
            role[k] = {"role": rname, "service": target if target in svc_addr else role.get(k, {}).get("service", ""), "how": "declared"}
    def main_peer(a):
        c = collections.Counter()
        for (s, d), n in pairs.items():
            for x, y in ((s, d), (d, s)):
                if x == a and y not in role and not addr_note(y):
                    c[y] += n
        return c.most_common(1)[0][0] if c else ""

    if stats and not any(v["how"] == "declared" for v in role.values()):
        have = {v["role"]: k for k, v in role.items()}
        if gen_role in have and vic_role not in have:       # one address missing from the record
            p = main_peer(have[gen_role])
            if p:
                role[p] = {"role": vic_role, "service": "", "how": "inferred"}
        elif vic_role in have and gen_role not in have:
            p = main_peer(have[vic_role])
            if p:
                role[p] = {"role": gen_role, "service": "", "how": "inferred"}
        elif not have:   # nothing recorded: name who opened the exchange, never guess who attacks
            gen_role, vic_role = "Initiator", "Responder"
            syn = next((r for r in rows if r["flags"] >= 0 and r["flags"] & 0x12 == 0x02 and r["src"]), None)
            first = syn or next((r for r in rows if r["src"] and not addr_note(r["src"])), None)
            if first:
                cli = first["src"]
                role[cli] = {"role": gen_role, "service": "", "how": "inferred"}
                srv = first["dst"] if syn and not addr_note(first["dst"]) else main_peer(cli)
                if srv and srv != cli:
                    role[srv] = {"role": vic_role, "service": "", "how": "inferred"}
    order = {gen_role: 0, vic_role: 1}
    out = []
    for a, s in stats.items():
        r = role.get(a)
        note = addr_note(a)
        if r:
            entry = dict(r)
        elif note:
            entry = {"role": f"Other ({note})", "service": "", "how": "address"}
        elif derived:
            src = derived[0][0] if len(derived) == 1 else "the source traces"
            entry = {"role": f"Other (from {src} or added by {script})", "service": "", "how": "address"}
        elif crafted:
            entry = {"role": "Other (crafted address)", "service": "", "how": "address"}
        elif svc_addr:
            entry = {"role": "Other (no lab container had it: spoofed or outside the lab)", "service": "", "how": "recorded"}
        else:
            entry = {"role": "Other host", "service": "", "how": "address"}
        svc = entry.get("service")
        sv = services.get(svc, {}) if svc else {}
        img = sv.get("image") or (f"built from {sv['build']}/" if sv.get("build") else "")
        entry.update({"addr": a, "mac": mac_of.get(a, ""), "image": img, **s})
        out.append(entry)
    out.sort(key=lambda e: (order.get(e["role"], 2 if e["how"] in ("declared", "recorded") and not e["role"].startswith("Other") else 3), -(e["sent"] + e["recv"])))
    return {"kind": kind, "gen": gen_role, "vic": vic_role, "rows": out, "pairs": pairs, "unresolved": unresolved,
            "crafted": crafted, "derived": derived, "script": script, "lab": bool(services), "inferred": any(e["how"] == "inferred" and not e["role"].startswith("Other") for e in out)}


def mm(s):
    """Text inside a Mermaid label or message: entity codes for the characters Mermaid parses."""
    return "".join(MM_ESC.get(c, c) for c in re.sub(r"[\x00-\x1f\x7f]", " ", str(s)))


def mm_label(e):
    return "<br/>".join(mm(x) for x in (e["role"], e["addr"], (f"service {e['service']}" if e["service"] else ""), e["image"]) if x)


def who_diagram(who):
    rows = who["rows"]
    shown = rows[:NODE_MAX]
    ids = {e["addr"]: f"n{i}" for i, e in enumerate(shown)}
    rest = rows[NODE_MAX:]
    L = ["```mermaid", "flowchart LR"]
    if who.get("derived"):
        title = f"derived from {', '.join(n for n, _ in who['derived'])} by {who['script']}: addresses from there"
    elif who["crafted"]:
        title = "crafted trace: addresses written by the generator, no network used"
    else:
        title = "lab network: internal, no route out" if who["lab"] else "hosts in the trace"
    L.append(f'  subgraph net["{mm(title)}"]')
    for e in shown:
        L.append(f'    {ids[e["addr"]]}["{mm_label(e)}"]')
    if rest:
        L.append(f'    others["{mm(f"{len(rest)} other address(es)")}"]')
    L.append("  end")
    edges = collections.Counter()
    for (s, d), n in who["pairs"].items():
        edges[(ids.get(s, "others"), ids.get(d, "others"))] += n
    for (s, d), n in edges.most_common(12):
        if s != d:
            L.append(f'  {s} -- "{n} frame{"s" if n != 1 else ""}" --> {d}')
    vic = next((e for e in shown if e["role"] == who["vic"] and e["how"] == "recorded"), None)
    if vic and not who["crafted"]:   # victim first, so the diagram reads attacker -> victim -> capture
        L.append(f'  {ids[vic["addr"]]} -.- cap(["{mm("capture: tcpdump in the network namespace of service victim")}"])')
    L.append("  classDef attacker stroke:#d33,stroke-width:3px")
    L.append("  classDef victim stroke:#36c,stroke-width:3px")
    for e in shown:
        if e["role"] in ("Attacker", "Victim"):
            L.append(f'  class {ids[e["addr"]]} {e["role"].lower()}')
    L.append("```")
    return "\n".join(L)


def seq_diagram(who, rows):
    """The first SEQ_ROWS frames as a sequence diagram, replies dashed. A trace that carries payloads keeps
    the frames that tell its story: payloads, non-TCP frames, connection openings (SYN) and resets; the
    handshake replies, FINs and pure ACKs are left out. A trace with no payload keeps all but pure ACKs."""
    app = any(r["tlen"] > 0 or r["flags"] < 0 for r in rows)
    if app:
        keep = lambda r: r["flags"] < 0 or r["tlen"] > 0 or r["flags"] & 0x04 or r["flags"] & 0x12 == 0x02
        left_out = "TCP SYN/ACK, FIN and ACK segments without payload"
    else:
        keep = lambda r: not (r["tlen"] == 0 and r["flags"] == 0x010)
        left_out = "pure TCP ACKs"
    shown = [r for r in rows if keep(r) and r["src"] and r["dst"]]
    if not shown:
        return "", ""
    head = shown[:SEQ_ROWS]
    label = {e["addr"]: e for e in who["rows"]}
    order = []
    for r in head:
        for a in (r["src"], r["dst"]):
            if a not in order:
                order.append(a)
    primary = [e["addr"] for e in who["rows"] if e["role"] in (who["gen"], who["vic"])]
    pos = {a: i for i, a in enumerate(order)}
    order = sorted(order, key=lambda a: (primary.index(a) if a in primary else len(primary), pos[a]))
    pid = {a: f"p{i}" for i, a in enumerate(order[:6])}
    many = len(order) > 6
    L = ["```mermaid", "sequenceDiagram"]
    for a in order[:6]:
        e = label.get(a, {"role": "Host", "addr": a})
        L.append(f"  participant {pid[a]} as {mm(e['role'])}<br/>{mm(a).replace(':', '#58;')}")
    if many:
        L.append(f"  participant px as {mm(f'{len(order) - 6} other addresses')}")
    servers = {e["addr"] for e in who["rows"] if e["role"] == who["vic"]}
    for r in head:
        s, d = pid.get(r["src"], "px"), pid.get(r["dst"], "px")
        info = TCP_NOISE.sub("", r["info"]).strip() if r["proto"] == "TCP" else r["info"]
        text = f"[{r['num']}] {r['t']:.3f} s {r['proto']} {info}".strip()
        text = text if len(text) <= SEQ_TEXT else text[:SEQ_TEXT - 1] + "…"
        L.append(f"  {s}{'-->>' if r['src'] in servers else '->>'}{d}: {mm(text)}")
    left = len(rows) - len(head)
    skipped = len(rows) - len(shown)
    if left > 0:
        ends = f"{pid[order[0]]},{pid[order[1]]}" if len(order) > 1 else pid[order[0]]
        L.append(f"  Note over {ends}: {mm(f'{left} more frame(s) not drawn' + (f', {skipped} of them {left_out}' if skipped else ''))}")
    L.append("```")
    caption = (f"{len(head)} of {len(rows)} frames, in order" + (f" ({left_out} left out)" if skipped else "")
               + f", from `tshark -n`: dashed arrows are sent by the {who['vic'].lower()}, solid ones by everyone else.")
    return "\n".join(L), caption


def time_chart(rows):
    """Frames per time bin (at most TIME_BINS bars), or '' for a trace too short to chart."""
    if len(rows) < 2:
        return ""
    end = max(r["t"] for r in rows)
    if end <= 0:
        return ""
    step = next((s for s in TIME_STEPS if end / s < TIME_BINS), TIME_STEPS[-1])
    n = int(end // step) + 1
    bins = [0] * n
    for r in rows:
        bins[min(int(r["t"] // step), n - 1)] += 1
    fmt = lambda x: f"{round(x, 3):g}"
    return "\n".join(["```mermaid", '%%{init: {"themeVariables": {"xyChart": {"plotColorPalette": "#3b6fd1"}}}}%%', "xychart-beta",
                      f'  title "Frames per {fmt(step)} s, all directions"',
                      '  x-axis "seconds since the first frame" [' + ", ".join(f'"{fmt(i * step)}"' for i in range(n)) + "]",
                      '  y-axis "frames"',
                      "  bar [" + ", ".join(str(b) for b in bins) + "]", "```"])


def protocol_pie(rows):
    c = collections.Counter(r["proto"] or "unknown" for r in rows)
    if not c:
        return ""
    top = c.most_common(PIE_SLICES)
    rest = sum(c.values()) - sum(n for _, n in top)
    L = ["```mermaid", "pie showData", "  title Frames by protocol (the top layer of each frame)"]
    L += [f'  "{mm(p)}" : {n}' for p, n in top]
    if rest:
        L.append(f'  "other" : {rest}')
    L.append("```")
    return "\n".join(L)


def generation_diagram(trace, crafted, prov, verified, command):
    """From the command to this document: the steps the trace went through, as a flowchart."""
    name = trace[:-5]
    g = prov.get("generator", "")
    if crafted:
        tool = "craft_pcap.py" if g.startswith("craft_pcap.py") else (g.split()[1] if g.startswith("python3 ") and len(g.split()) > 1 else "the generator")
        steps = [f"cyberlab craft {trace}", f"{tool} in the tools container, no network"]
        pcap = f"out/{trace}"
    else:
        steps = [f"cyberlab run, mode {(prov.get('env') or {}).get('MODE', name)}",
                 "isolation policy checked; lab up on an internal network",
                 "generator sends the traffic; tcpdump captures it in the victim's namespace"]
        pcap = f"out/{trace}, {prov.get('dropped', '?')} packets dropped"
    if not command:
        steps[0] = "command not recorded"
    nodes = [f'["{mm(s)}"]' for s in steps] + [f'[("{mm(pcap)}")]']
    if not crafted:
        nodes.append(f'["{mm("teardown checked: nothing left")}"]')
    nodes += [f'["{mm("verify against expect.json: " + verified)}"]', f'["{mm(f"out/{name}.md")}"]']
    L = ["```mermaid", "flowchart LR"] + [f"  s{i}{n}" for i, n in enumerate(nodes)]
    L.append("  " + " --> ".join(f"s{i}" for i in range(len(nodes))))
    L.append("```")
    return "\n".join(L)


KNOWN_FROM = {"recorded": "Docker, while the lab ran", "crafted": "craft_pcap.py's fixed addresses",
              "declared": "`Roles:` line in mechanism.md", "inferred": "inferred from the trace", "address": "the address itself"}


def who_section(who):
    """## Who is who: one sentence, a diagram and a table of every address, before any detail."""
    rows = who["rows"]
    prim = [e for e in rows if not e["role"].startswith("Other")]

    def image(e):
        return "" if not e["image"] else (f"built from `{e['image'][11:]}`" if e["image"].startswith("built from ") else f"`{e['image']}`")

    def name(e):
        extra = ", ".join(x for x in ((f"lab service `{e['service']}`" if e["service"] else ""), image(e)) if x)
        return f"**{e['role']} `{e['addr']}`**" + (f" ({extra})" if extra else "")

    L = ["## Who is who", ""]
    if not rows:
        return L + ["_No IP or MAC address could be read from the trace._", ""]
    pair = [e for e in prim if e["role"] in (who["gen"], who["vic"])]
    if len(pair) == 2 and pair[0]["role"] == who["gen"]:
        verb = "opened the exchange with" if who["gen"] == "Initiator" else ("attacks" if who["gen"] == "Attacker" else "talks to")
        s = f"{name(pair[0])} {verb} {name(pair[1])}."
        rest = [e for e in prim if e not in pair]
        if rest:
            s += " Also: " + "; ".join(name(e) for e in rest) + "."
    else:
        s = "; ".join(name(e) for e in prim) + "." if prim else "No host role could be told from the trace."
    if who.get("derived"):
        srcs = [f"`{n}`" + (f" ({d})" if d else "") for n, d in who["derived"]]
        srcs = srcs[0] if len(srcs) == 1 else ", ".join(srcs[:-1]) + " and " + srcs[-1]
        whose = "that trace's" if len(who["derived"]) == 1 else "those traces'"
        s += (f" The trace is derived from {srcs}: `{who['script']}` edited or added frames, so its addresses are "
              f"{whose} unless the script wrote them.")
    elif who["crafted"]:
        s += " The trace is crafted: the generator wrote these addresses, and no host or network was involved."
    elif who["lab"]:
        s += " The capture ran in the victim's network namespace: the trace shows the traffic as the victim saw it."
    others = [e for e in rows if e["role"].startswith("Other")]
    if others:
        s += f" {len(others)} other address(es) appear in the table."
    L += [s, "", who_diagram(who), ""]
    L += ["| Role | Address | MAC | Lab service (image) | Frames sent | Frames received | Known from |",
          "|---|---|---|---|---|---|---|"]
    for e in rows[:ROLE_ROWS]:
        svc = f"`{e['service']}`" + (f" ({image(e)})" if e["image"] else "") if e["service"] else "—"
        L.append(f"| {md_cell(e['role'])} | `{e['addr']}` | {('`' + e['mac'] + '`') if e['mac'] else '—'} | {md_cell(svc)} | {e['sent']} | {e['recv']} | {KNOWN_FROM.get(e['how'], e['how'])} |")
    if len(rows) > ROLE_ROWS:
        more = rows[ROLE_ROWS:]
        L.append(f"| … | {len(more)} more address(es) | | | {sum(e['sent'] for e in more)} | {sum(e['recv'] for e in more)} | |")
    L.append("")
    if who["inferred"] and who["gen"] == "Initiator":
        L.append("_Not recorded: the initiator is the host that sent the first TCP SYN (or, with no SYN, the first frame), "
                 "the responder its main peer. Which one attacks is not known from the trace (in a lab capture the initiator is "
                 "normally the `generator` service). A `Roles:` line at the top of this trace's section in `mechanism.md` names them._")
        L.append("")
    elif who["inferred"]:
        L.append("_One address was not recorded and is taken as the main peer of the other. A `Roles:` line at the top of "
                 "this trace's section in `mechanism.md` names it for certain._")
        L.append("")
    elif any(e["how"] == "recorded" for e in prim):
        L.append(f"_The lab's `generator` service is the {who['gen'].lower()} and its `victim` service the {who['vic'].lower()}: "
                 "the generator is called the attacker only in attack traces (name starting with `attack`, or a `Traces:` line "
                 "saying the rule fires). Docker assigns the addresses on each run._")
        L.append("")
    return L


def render(lab, trace, mission, expect, verify, now, lab_name="", mech=None, rows=None, who=None):
    name = trace[:-5]
    path = os.path.join(lab, "out", trace)
    prov_path = os.path.join(lab, "out", name + ".provenance.json")
    prov = {}
    if os.path.isfile(prov_path):
        try:
            prov = json.load(open(prov_path))
        except json.JSONDecodeError:
            prov = {}
    info = capinfo(path)
    lab_name = lab_name or prov.get("lab") or os.path.basename(os.path.normpath(lab))
    origin = prov.get("origin", "unknown (no provenance file)")
    crafted = origin.startswith("crafted")
    digest = sha256(path)
    recorded_sha = prov.get("sha256", "")
    f = mission["fields"]
    v = verify.get(trace, {})
    checks = v.get("checks", [])
    passed = bool(checks) and all(c.get("ok") for c in checks)
    status = "not verified yet" if not checks else ("PASS" if passed else f"FAIL ({sum(1 for c in checks if not c.get('ok'))} failed check(s))")
    command = prov.get("command") or legacy_command(prov, lab_name, trace)
    recorded = prov.get("inputs_recorded") == "at generation"
    inputs_now = lab_inputs(lab)
    inputs = prov.get("inputs") if recorded else inputs_now
    s = trace_summaries(path)
    mech = mech or {}
    rows = frame_rows(path) if rows is None else rows
    who = who_is_who(trace, prov, mech, mission, rows, lab) if who is None else who

    L = []
    L.append(f"# {trace}")
    L.append("")
    L.append(f"<!-- Generated by cyberlab {prov.get('cyberlab_version', '')} on {now}; regenerate with: cyberlab doc <lab> {trace} -->".replace("  ", " "))
    L.append("")
    desc = mission["traces"].get(trace, "")
    L.append(desc[:1].upper() + desc[1:] + ("" if desc.endswith(".") else ".") if desc else
             "_No `Traces:` line for this trace in mission.md: add one to describe what it must show._")
    L.append("")
    table = [
        ("Mission", mission["goal"] or "—"),
        ("Lab", f"`{lab_name}`"),
        ("Origin", f"**{origin}**"),
        ("Created", prov.get("created_at", "—")),
        ("Frames", f"{info.get('Number of packets', prov.get('frames', '?'))} ({info.get('File encapsulation', '?')}, {info.get('File type', '?')})"),
        ("Duration", f"{info.get('Capture duration', '?')} (first packet {info.get('First packet time', '?')} UTC)"),
        ("Size", info.get("File size", "?")),
        ("SHA-256", f"`{digest}`"),
        ("Verification", f"{status} against `expect.json`"),
        ("cyberlab", prov.get("cyberlab_version", "unrecorded (generated before trace documents existed)")),
    ]
    L.append("| | |")
    L.append("|---|---|")
    L += [f"| {k} | {md_cell(val)} |" for k, val in table]
    L.append("")
    if recorded_sha and recorded_sha != digest:
        L.append(f"> **Warning:** the file's sha256 differs from the one recorded at generation (`{recorded_sha}`): it was changed after cyberlab wrote it.")
        L.append("")

    # ---- Who is who: before any detail, so every address below has a name
    L += who_section(who)

    # ---- What it contains
    L.append("## What it contains")
    L.append("")
    if f.get("Protocol"):
        L.append(f"- **Protocol:** {f['Protocol']}")
    if f.get("Consumer"):
        L.append(f"- **Made for:** {f['Consumer']}")
    if f.get("Scope"):
        L.append(f"- **Mission scope:** {f['Scope']}")
    mode = name
    requests = [l for l in mission["log"] if re.search(rf"(?<![\w-]){re.escape(mode)}(\.pcap)?(?![\w-])", l.split("→", 1)[-1])]
    for r in requests:
        L.append(f"- **Requested:** {r}")
    L.append("")
    seq, caption = seq_diagram(who, rows)
    if seq:
        L += ["### Exchange", "", caption, "", seq, ""]
    chart = time_chart(rows)
    if chart:
        L += ["### Traffic over time", "", chart, ""]
    pie = protocol_pie(rows)
    if pie:
        L += ["### Protocols", "", pie, ""]
    if s.get("phs") or s.get("conv") or s.get("packets"):
        L += ["<details>", f"<summary>tshark output: protocol hierarchy, conversations, first {PACKET_ROWS} packets</summary>", ""]
    if s.get("phs"):
        L.append("Protocol hierarchy (`tshark -qz io,phs`):")
        L.append("")
        L.append(block(s["phs"]))
        L.append("")
    if s.get("conv"):
        kind, text, n = s["conv"]
        label = {"ip": "IPv4", "ipv6": "IPv6", "eth": "Ethernet"}[kind]
        L.append(f"{label} conversations ({n}, `tshark -qz conv,{kind}`):")
        L.append("")
        L.append(block(text))
        L.append("")
    if s.get("packets"):
        total = int(info.get("Number of packets", "0") or 0)
        more = f" (first {PACKET_ROWS} of {total})" if total > PACKET_ROWS else ""
        L.append(f"Packets{more} (`tshark -n -r {trace}`):")
        L.append("")
        L.append(block(s["packets"] + (f"\n… {total - PACKET_ROWS} more" if total > PACKET_ROWS else "")))
        L.append("")
    if s.get("phs") or s.get("conv") or s.get("packets"):
        L += ["</details>", ""]

    # ---- Mechanism
    L.append("## Mechanism" + (f": {mech['title']}" if mech.get("title") else ""))
    L.append("")
    if mech.get("found"):
        if mech.get("body"):
            L.append(mech["body"])
            L.append("")
        own = mech.get("traces", {}).get(trace) or mech.get("traces", {}).get(name)
        L.append("### In this trace")
        L.append("")
        L.append(own or f"_`mechanism.md` has no `## {trace}` section: the text above may describe another trace or the template this lab came from. Add the section, then run `cyberlab doc <lab>`._")
        L.append("")
        if mech.get("refs"):
            L.append("### References")
            L.append("")
            L.append(mech["refs"])
            L.append("")
        else:
            L.append("_`mechanism.md` lists no references._")
            L.append("")
    else:
        L.append("_Not written yet: add `mechanism.md` to the lab (how the attack or protocol works, what this trace shows of it, references), then run `cyberlab doc <lab>`._")
        L.append("")

    # ---- Checks
    L.append("## What was checked")
    L.append("")
    exps = (expect.get("traces") or {}).get(trace)
    if exps is not None:
        L.append(f"Expectations in `expect.json` (written from the mission before the trace was generated):")
        L.append("")
        L.append(block("[\n" + ",\n".join("  " + json.dumps(e, ensure_ascii=False) for e in exps) + "\n]" if isinstance(exps, list) else json.dumps(exps), "json"))
        L.append("")
    else:
        L.append("_`expect.json` has no entry for this trace._")
        L.append("")
    if checks:
        L.append(f"Result of the last `cyberlab verify` (`out/verify.json`): **{status}**")
        L.append("")
        L += [f"- {'PASS' if c.get('ok') else 'FAIL'} {c.get('check', '')}" for c in checks]
        L.append("")
    if not crafted and "dropped" in prov:
        L.append(f"Lab checks at generation: isolation policy, running-lab isolation and teardown passed; the generator exited {prov.get('generator_exit', '?')}; tcpdump dropped {prov.get('dropped')} packet(s).")
        L.append("")

    # ---- How it was generated
    L.append("## How it was generated")
    L.append("")
    L.append(generation_diagram(trace, crafted, prov, f"{len(checks)} checks, {status}" if checks else status, command))
    L.append("")
    if f.get("Generator"):
        L.append(f"- **Generator:** {f['Generator']}")
    if f.get("Server/client"):
        L.append(f"- **Server/client:** {f['Server/client']}")
    if command:
        L.append(f"- **Command:** `{command}`" + ("" if prov.get("command") else " (reconstructed from the provenance" + ("; argument quoting was not recorded)" if " -- " in command else ")")))
    if prov.get("env"):
        L.append("- **Environment:** " + ", ".join(f"`{k}={val}`" for k, val in prov["env"].items()))
    L.append("")
    if crafted:
        L.append("The trace was written by a script in the tools image with no network (`--network none`): every byte comes from the inputs below, nothing was captured.")
        L.append("")
    services = prov.get("services")
    if services:
        L.append("Lab services (resolved `docker-compose.yml` for this mode; one internal network, no published ports):")
        L.append("")
        L.append("| Service | Image or build | Runs |")
        L.append("|---|---|---|")
        for sname, sv in services.items():
            img = sv.get("image", "")
            if sv.get("build"):
                img = f"built from `{sv['build']}/{sv.get('dockerfile', 'Dockerfile')}`" + (f" as `{img}`" if img else "")
            elif img:
                img = f"`{img}`"
            runs = sv.get("command") or sv.get("entrypoint") or ""
            if isinstance(runs, list):
                runs = " ".join(runs)
            runs = f"`{md_cell(runs)}`" if runs else "the image's default command"
            extra = f" (network of `{sv['network_mode']}`)" if str(sv.get("network_mode", "")).startswith("service:") else ""
            L.append(f"| {sname} | {md_cell(img)} | {runs}{extra} |")
        L.append("")
    details = prov.get("image_details") or []
    bases = prov.get("base_images") or []
    if details or bases or prov.get("images"):
        L.append("Images at generation:")
        L.append("")
        if details or bases:
            L.append("| Image | Image ID | Registry digest | Platform |")
            L.append("|---|---|---|---|")
            local = {(prov.get("tools") or {}).get("image", "cyberlab/tools:local")}
            proj = prov.get("project", "")
            for sname, sv in (services or {}).items():
                if sv.get("build"):
                    local.add(sv.get("image") or f"{proj}-{sname}")
            for d in details:
                tag = (d.get("tags") or ["(untagged)"])[0]
                built = tag in local or tag.split(":")[0] in local or (proj and tag.startswith(proj + "-"))
                dig = "built locally (rebuild it from its Dockerfile)" if built else (", ".join(f"`{x}`" for x in d.get("repo_digests", [])) or "—")
                L.append(f"| `{tag}` | `{d.get('id', '')[:19]}` | {dig} | {d.get('platform', '')} |")
            for b in bases:
                L.append(f"| base `{b['ref']}` | `{b.get('id', '')[:19]}` | {', '.join(f'`{x}`' for x in b.get('repo_digests', [])) or '—'} | {b.get('platform', '')} |")
        else:
            L += [f"- `{i}`" for i in prov["images"]]
        L.append("")
    if prov.get("tools") or prov.get("host"):
        t = prov.get("tools", {})
        h = prov.get("host", {})
        if t:
            L.append(f"- **Tools image:** `{t.get('image', '')}` `{t.get('id', '')[:19]}` ({t.get('versions', '')})")
        if h:
            L.append(f"- **Host:** Docker {h.get('docker', '?')} on {h.get('platform', '?')}")
        L.append("")
    if prov.get("lab_traces_at_generation"):
        L.append("Traces in `out/` that the script names, as they were when it ran (it derives this trace from them):")
        L.append("")
        L += [f"- `{n}` `{h}`" for n, h in prov["lab_traces_at_generation"].items()]
        L.append("")
    if inputs:
        when = "recorded at generation" if recorded else f"taken on {now}, when this document was written: the trace predates recorded inputs, so these files may have changed since it was generated"
        L.append(f"Lab input files ({when}; paths relative to the lab directory):")
        L.append("")
        L.append("| File | SHA-256 | Now |")
        L.append("|---|---|---|")
        for p, h in inputs.items():
            cur = inputs_now.get(p)
            state = "same" if cur == h else ("**changed**" if cur else "**missing**")
            L.append(f"| [`{p}`](../{p}) | `{h[:16]}…` | {state if recorded else '—'} |")
        if recorded:
            for p in inputs_now:
                if p not in inputs:
                    L.append(f"| [`{p}`](../{p}) | — | added later |")
        L.append("")
        if recorded and any(inputs_now.get(p) != h for p, h in inputs.items()):
            L.append("> Some inputs changed after this trace was generated (a later request edited the lab). Restore the recorded versions before reproducing it byte for byte, or expect the differences those edits make.")
            L.append("")
    log = os.path.join(lab, "out", name + ".generator.log")
    if os.path.isfile(log):
        tail = open(log, errors="replace").read().splitlines()[-LOG_TAIL:]
        if tail:
            L.append(f"Generator output (last {len(tail)} lines of [`{name}.generator.log`]({name}.generator.log)):")
            L.append("")
            L.append(block("\n".join(tail)))
            L.append("")

    # ---- How to reproduce
    L.append("## How to reproduce")
    L.append("")
    ver = prov.get("cyberlab_version")
    L.append(f"1. Install Docker with Compose v2 and the cyberlab skill{f' (version {ver})' if ver else ''} from https://github.com/montimage-projects/cyberlab, then build its tools image: `cyberlab build`.")
    L.append(f"2. Copy this lab directory (`{lab_name}`) with the input files listed above; check their sha256. `mission.md` and `expect.json` come with it.")
    if command:
        L.append(f"3. Run `{command.replace('<lab>', '<lab-dir>')}` with the copy as `<lab-dir>`. It regenerates `out/{trace}` and verifies it against `expect.json`; it ends with `RESULT PASS` when the new trace shows what this one shows.")
    else:
        L.append("3. Regenerate the trace with the command that made it (not recorded) and verify it with `cyberlab verify <lab-dir> " + trace + "`.")
    L.append("")
    g = prov.get("generator", "")
    if not crafted:
        L.append("**What \"the same\" means for a lab capture.** A rerun gives an equivalent trace, not the same file: timestamps, TCP initial sequence numbers, client ports, the addresses Docker assigns and the server's own timing change on every run, so the sha256 will differ. The rerun is equivalent when the expectations above pass and the packet list shows the same exchange (same messages, same order, same counts).")
        L.append("")
        L.append("To get closer to the original:")
        L.append("")
        L.append("- Use the same image versions. Pull by the registry digests in *Images at generation* (`image: name@sha256:…`) instead of a tag that may have moved.")
        L.append("- Built images (`build:`) are rebuilt from their Dockerfiles. Packages installed without a version (apk, apt, pip) can resolve to newer releases: pin them, or reuse the base image digests above.")
        L.append("- Run on the same CPU architecture: arm64 and amd64 hosts pull different image variants.")
    elif "--script" not in command and not g.startswith("python3 "):
        L.append(f"**Same file.** `craft_pcap.py` is deterministic: fixed addresses, ports and sequence numbers, timestamps 1 ms apart from `--start` (default 1700000000). The same inputs give the same bytes, so the rerun's sha256 must be `{digest}`.")
    else:
        script = re.match(r"python3 (\S+)", g)
        sname = script.group(1) if script else "the script"
        L.append(f"**Same file only if `{sname}` is deterministic.** Rerun it from the same inputs and compare the sha256 with `{digest}`. A script that reads the clock or random numbers gives a different file each time; one that derives this trace from another trace in `out/` gives the same file only from that same source trace" + (" (see the list above)." if prov.get("lab_traces_at_generation") else ": regenerate or keep that trace first.") + " The expectations still decide whether the rerun shows what this trace shows.")
    L.append("")
    return "\n".join(L).rstrip() + "\n"


def doc_warnings(lab, trace, mission, mech, verify, who=None):
    """What keeps a trace's document from being complete: each one is printed as a WARN line."""
    w = []
    if trace not in mission["traces"]:
        w.append("no `- Traces: " + trace + " — …` line in mission.md (the document has no description)")
    if not mech.get("found"):
        w.append("no mechanism.md in the lab (the document has no Mechanism section)")
    else:
        sec = trace if trace in mech["traces"] else (trace[:-5] if trace[:-5] in mech["traces"] else None)
        if sec is None:
            w.append(f"mechanism.md has no `## {trace}` section")
        elif not mech["diagrams"].get(sec):
            w.append(f"mechanism.md's `## {trace}` section has no Mermaid diagram (a ```mermaid block of what this trace holds)")
        if not mech["diagrams"].get(""):
            w.append("mechanism.md has no Mermaid diagram before its first `##` section (a sequenceDiagram of how the attack or protocol works)")
        for key, lines in mech["blocks"]:
            if key in ("", sec):   # the text this trace's document shows
                where = "general text" if key == "" else f"`## {key}` section"
                w += [f"mechanism.md, Mermaid diagram in the {where}: {i}" for i in mermaid_lint(lines)]
        if not mech.get("refs"):
            w.append("mechanism.md has no `## References` list")
    if who:
        if who["inferred"]:
            w.append(f"who is who was inferred from the trace: open mechanism.md's `## {trace}` section with "
                     "`Roles: <role> = <lab service or address>, ...`")
        for r, t, why in who["unresolved"]:
            w.append(f"`Roles: {r} = {t}` in mechanism.md matches no address in the trace"
                     + (f": {why}; name the host by its IP address" if why else ""))
    checks = verify.get(trace, {}).get("checks", [])
    if not checks:
        w.append("not verified: run cyberlab verify")
    elif not all(c.get("ok") for c in checks):
        w.append("verification FAIL")
    prov_path = os.path.join(lab, "out", trace[:-5] + ".provenance.json")
    try:
        prov = json.load(open(prov_path))
    except (OSError, json.JSONDecodeError):
        prov = None
    if prov is None:
        w.append("no provenance file")
    elif prov.get("inputs_recorded") != "at generation":
        w.append("lab inputs not recorded at generation (trace made before trace documents existed)")
    else:
        now = lab_inputs(lab)
        changed = [p for p, h in prov.get("inputs", {}).items() if now.get(p) != h]
        if changed:
            w.append("lab inputs changed since generation: " + ", ".join(changed))
        reads = script_reads(lab, prov.get("command"), prov.get("generator"))
        for n, h in (prov.get("lab_traces_at_generation") or {}).items():
            if reads is not None and n not in reads:
                continue   # the script never names this trace: it cannot be a source
            src = os.path.join(lab, "out", n)
            if not os.path.isfile(src) or sha256(src) != h:
                w.append(f"out/{n}, present when this trace was generated by a script that may read it, changed since: regenerate this trace if it derives from {n}")
    return w


def cmd_doc(a):
    out_dir = os.path.join(a.lab, "out")
    names = a.trace or (sorted(n for n in os.listdir(out_dir) if n.endswith(".pcap")) if os.path.isdir(out_dir) else [])
    if not names:
        die(f"no traces in {out_dir}.")
    mission = read_mission(a.lab)
    mech = read_mechanism(a.lab)
    try:
        expect = json.load(open(os.path.join(a.lab, "expect.json")))
    except (OSError, json.JSONDecodeError):
        expect = {}
    try:
        verify = json.load(open(os.path.join(out_dir, "verify.json")))
    except (OSError, json.JSONDecodeError):
        verify = {}
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rc = 0
    for t in names:
        path = os.path.join(out_dir, t)
        if not os.path.isfile(path):
            print(f"FAIL doc {t}: out/{t} not found")
            rc = 1
            continue
        try:
            prov = json.load(open(os.path.join(out_dir, t[:-5] + ".provenance.json")))
        except (OSError, json.JSONDecodeError):
            prov = {}
        rows = frame_rows(path)
        who = who_is_who(t, prov, mech, mission, rows, a.lab)
        write_atomic(os.path.join(out_dir, t[:-5] + ".md"), render(a.lab, t, mission, expect, verify, now, a.lab_name, mech, rows, who))
        warns = doc_warnings(a.lab, t, mission, mech, verify, who)
        print(f"PASS doc   out/{t[:-5]}.md" + (f" ({len(warns)} warning(s))" if warns else ""))
        for w in warns:
            print(f"WARN doc   {t}: {w}")
    sys.exit(rc)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lab-files")
    p.add_argument("--lab", required=True)
    p = sub.add_parser("provenance")
    p.add_argument("--lab", required=True)
    p.add_argument("--trace", required=True)
    p.add_argument("--origin", required=True)
    p.add_argument("--generator", required=True)
    p.add_argument("--command", required=True)
    p.add_argument("--version", default="")
    p.add_argument("--tools-image", default="cyberlab/tools:local")
    p = sub.add_parser("doc")
    p.add_argument("--lab", required=True)
    p.add_argument("--trace", action="append")
    p.add_argument("--lab-name", default="", help="the lab directory's name on the host")
    a = ap.parse_args()
    if not os.path.isdir(a.lab):
        die(f"lab directory {a.lab} not found.")
    if a.cmd == "lab-files":
        json.dump({"inputs": lab_inputs(a.lab), "froms": dockerfile_froms(a.lab)}, sys.stdout)
    elif a.cmd == "provenance":
        cmd_provenance(a)
    else:
        cmd_doc(a)


if __name__ == "__main__":
    main()
