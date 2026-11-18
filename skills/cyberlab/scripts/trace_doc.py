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
      Writes <dir>/out/<name>.md for each trace (default: every out/*.pcap): what the trace contains,
      how the attack (or protocol) works, how it was generated, what was checked, and how to
      reproduce it. Built from mission.md, mechanism.md,
      expect.json, out/verify.json, out/<name>.provenance.json and tshark summaries of the trace.

Only the Python standard library, capinfos and tshark are used. Exit: 0 ok, 1 usage or input error.
"""
import argparse
import datetime as dt
import hashlib
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
    for k in ("project", "generator_exit", "dropped", "images"):
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
    """mechanism.md split into its title, general text, per-trace sections and references."""
    m = {"title": "", "body": [], "traces": {}, "refs": [], "found": False}
    p = os.path.join(lab, "mechanism.md")
    if not os.path.isfile(p):
        return m
    m["found"] = True
    cur = m["body"]
    for line in open(p, errors="replace"):
        line = line.rstrip("\n")
        h1 = re.match(r"#\s+(?:Mechanism:\s*)?(.*)", line)
        h2 = re.match(r"##\s+(.*)", line)
        if h1 and not line.startswith("##"):
            m["title"] = h1.group(1).strip()
        elif h2:
            name = h2.group(1).strip().strip("`")
            cur = m["refs"] if name.lower() in ("references", "sources") else m["traces"].setdefault(name, [])
        else:
            cur.append(re.sub(r"^(#{3,})", r"#\1", line))   # keep deeper headings below the doc's own
    for k in ("body", "refs"):
        m[k] = "\n".join(m[k]).strip()
    m["traces"] = {k: "\n".join(v).strip() for k, v in m["traces"].items()}
    return m


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


def render(lab, trace, mission, expect, verify, now, lab_name="", mech=None):
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

    L = []
    L.append(f"# {trace}")
    L.append("")
    L.append(f"<!-- Generated by cyberlab {prov.get('cyberlab_version', '')} on {now}; regenerate with: cyberlab doc <lab> {trace} -->".replace("  ", " "))
    L.append("")
    desc = mission["traces"].get(trace, "")
    L.append(desc[:1].upper() + desc[1:] + ("" if desc.endswith(".") else ".") if desc else
             "_No `Traces:` line for this trace in mission.md: add one to describe what it must show._")
    L.append("")
    rows = [
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
    L += [f"| {k} | {md_cell(val)} |" for k, val in rows]
    L.append("")
    if recorded_sha and recorded_sha != digest:
        L.append(f"> **Warning:** the file's sha256 differs from the one recorded at generation (`{recorded_sha}`): it was changed after cyberlab wrote it.")
        L.append("")

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

    # ---- Mechanism
    mech = mech or {}
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


def doc_warnings(lab, trace, mission, mech, verify):
    """What keeps a trace's document from being complete: each one is printed as a WARN line."""
    w = []
    if trace not in mission["traces"]:
        w.append("no `- Traces: " + trace + " — …` line in mission.md (the document has no description)")
    if not mech.get("found"):
        w.append("no mechanism.md in the lab (the document has no Mechanism section)")
    else:
        if trace not in mech["traces"] and trace[:-5] not in mech["traces"]:
            w.append(f"mechanism.md has no `## {trace}` section")
        if not mech.get("refs"):
            w.append("mechanism.md has no `## References` list")
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
        if not os.path.isfile(os.path.join(out_dir, t)):
            print(f"FAIL doc {t}: out/{t} not found")
            rc = 1
            continue
        write_atomic(os.path.join(out_dir, t[:-5] + ".md"), render(a.lab, t, mission, expect, verify, now, a.lab_name, mech))
        warns = doc_warnings(a.lab, t, mission, mech, verify)
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
