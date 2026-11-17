#!/usr/bin/env python3
"""Check traces against a mission's expectations. Runs INSIDE the tools image (`cyberlab verify`).

Usage: verify.py --lab <dir> [--trace <name.pcap>]...     (default: every trace in expect.json)

<dir>/expect.json:
  {
    "max_frames": 10000,                       # optional, default 10000
    "traces": {
      "attack.pcap": [
        {"filter": "ftp.response.code == 530", "min": 5},
        {"filter": "ftp", "min": 1, "endpoints": 2}     # frames from >= 2 distinct sources
      ],
      "benign.pcap": [
        {"filter": "ftp", "min": 1},
        {"filter": "ftp.response.code == 530", "max": 0}
      ]
    }
  }

Each trace (in <dir>/out/) is first checked to be readable, Ethernet (or Linux cooked/raw IP),
non-empty and at most max_frames frames. Then each expectation counts the frames matching its
tshark display filter: PASS when min <= count <= max (min defaults to 1, or 0 when max is given; max to unbounded);
"endpoints": N also requires N distinct sources (ip.src, ipv6.src or eth.src) among them.
"count_field": F (with optional "count_value": V) counts occurrences of field F (equal to V) in the
matching frames instead of frames: use it when one packet carries several messages (HTTP/2,
SCTP chunks, pipelined requests), e.g. {"filter": "http2.type == 3", "count_field": "http2.type",
"count_value": "3", "min": 90}.
Prints PASS/FAIL lines, writes <dir>/out/verify.json, exits 0 when everything passed,
2 when a check failed, 1 on a usage or input error.
"""
import argparse
import json
import os
import subprocess
import sys

LINKTYPES_OK = ("ether", "linux cooked", "linux-sll", "raw ip", "rawip", "raw")


def die(msg):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def trace_info(path):
    rc, out, err = run(["capinfos", "-M", "-c", "-E", "-u", path])
    if rc != 0:
        return None, f"capinfos cannot read it: {err.strip()[:200]}"
    info = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    rc, out, _ = run(["sha256sum", path])
    return {"frames": int(info.get("Number of packets", "0") or 0),
            "linktype": info.get("File encapsulation", "?"),
            "duration": info.get("Capture duration", "?"),
            "sha256": out.split()[0] if rc == 0 else "?"}, None


def count(path, flt, endpoints, field=None, value=None):
    """Frames matching flt (or, with field, occurrences of field[=value] in them) and distinct sources."""
    fields = ["-e", field or "frame.number"] + (["-e", "ip.src", "-e", "ipv6.src", "-e", "eth.src"] if endpoints else [])
    rc, out, err = run(["tshark", "-n", "-r", path, "-Y", flt, "-T", "fields", "-E", "separator=|"] + fields)
    if rc != 0:
        return None, None, err.strip().splitlines()[0] if err.strip() else f"tshark exit {rc}"
    rows = [r for r in out.splitlines() if r.strip()]
    n = len(rows)
    if field:
        vals = [v for r in rows for v in r.split("|")[0].split(",") if v != ""]
        n = sum(1 for v in vals if value is None or v == str(value))
    srcs = set()
    if endpoints:
        for r in rows:
            parts = r.split("|")
            src = next((p for p in parts[1:] if p), "")
            if src:
                srcs.add(src)
    return n, len(srcs), None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--lab", required=True, help="lab directory holding expect.json and out/")
    ap.add_argument("--trace", action="append", help="check only this trace (repeatable)")
    a = ap.parse_args()
    exp_path = os.path.join(a.lab, "expect.json")
    if not os.path.isfile(exp_path):
        die(f"{exp_path} not found. Write the mission's expectations there (references/mission.md).")
    try:
        exp = json.load(open(exp_path))
    except json.JSONDecodeError as e:
        die(f"{exp_path} is not valid JSON ({e}).")
    traces = exp.get("traces")
    if not isinstance(traces, dict) or not traces:
        die(f"{exp_path} has no \"traces\" object. Example: {{\"traces\": {{\"capture.pcap\": [{{\"filter\": \"tcp.port == 6379\"}}]}}}}")
    max_frames = int(exp.get("max_frames", 10000))
    names = a.trace or list(traces)
    unknown = [n for n in names if n not in traces]
    if unknown:
        die(f"no expectations for {', '.join(unknown)} in expect.json (it lists {', '.join(traces)}).")

    failed, report = 0, {}
    for name in names:
        path = os.path.join(a.lab, "out", name)
        rep = report[name] = {"checks": []}

        def res(ok, what):
            nonlocal failed
            failed += 0 if ok else 1
            rep["checks"].append({"ok": ok, "check": what})
            print(f"{'PASS' if ok else 'FAIL'} {name}: {what}")

        if not os.path.isfile(path):
            res(False, f"missing ({path}); generate it with `cyberlab run` or `cyberlab craft`")
            continue
        info, err = trace_info(path)
        if err:
            res(False, err)
            continue
        rep.update(info)
        res(info["linktype"].lower().startswith(LINKTYPES_OK), f"link type {info['linktype']} (Ethernet, Linux cooked or raw IP)")
        res(0 < info["frames"] <= max_frames, f"{info['frames']} frames (1..{max_frames})")
        exps = traces[name] if isinstance(traces[name], list) else []
        if not any(isinstance(e, dict) and e.get("filter") and int(e.get("min", 0 if "max" in e else 1)) >= 1 for e in exps):
            res(False, "no positive expectation (a filter with min >= 1): an empty or absent-only check proves nothing")
        for e in exps:
            flt = e.get("filter")
            if not flt:
                res(False, f"expectation without a filter: {e}")
                continue
            lo, hi, ep = int(e.get("min", 0 if "max" in e else 1)), e.get("max"), e.get("endpoints")
            cf, cv = e.get("count_field"), e.get("count_value")
            n, nsrc, terr = count(path, flt, bool(ep), cf, cv)
            if terr:
                res(False, f"tshark rejects filter '{flt}': {terr}")
                continue
            ok = n >= lo and (hi is None or n <= int(hi))
            rng = f"{lo}..{hi if hi is not None else '∞'}"
            unit = f"{cf}{'=' + str(cv) if cv is not None else ''} occurrence(s)" if cf else "frame(s)"
            what = f"'{flt}' matches {n} {unit}, expected {rng}"
            if ep:
                ok = ok and nsrc >= int(ep)
                what += f"; {nsrc} distinct source(s), expected >= {ep}"
            res(ok, what)
    out_path = os.path.join(a.lab, "out", "verify.json")
    try:
        merged = json.load(open(out_path)) if os.path.isfile(out_path) else {}
    except (OSError, json.JSONDecodeError):
        merged = {}
    merged.update(report)  # keep earlier traces' results: one file holds the whole mission's evidence
    try:
        json.dump(merged, open(out_path, "w"), indent=1)
    except OSError:
        pass
    print(f"RESULT {'PASS' if failed == 0 else 'FAIL'} ({failed} failed check(s))")
    sys.exit(0 if failed == 0 else 2)


if __name__ == "__main__":
    main()
