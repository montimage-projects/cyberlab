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
Rate, spread and spacing (what a time-window rule keys on). With window or distinct set, min and
max bound that measure, not the number of matching frames; the two cannot be combined in one
expectation (write two):
  "window": T      the most matches in any T-second window, e.g. {"filter": "dicom.pdu.type == 1",
                   "window": 5, "min": 21} (attack above a ">20 in 5 s" threshold) or "max": 20 (benign
                   below it); counts count_field occurrences when count_field is set.
  "distinct": F    the number of distinct values of field F among the matches, e.g.
                   {"filter": "tcp.flags.syn == 1 && tcp.flags.ack == 0", "distinct": "tcp.dstport", "min": 1000}.
  "gap_min": S / "gap_max": S   every interval between consecutive matches is >= / <= S seconds
                   (needs 2 matches), e.g. one attempt every 20 s: "gap_min": 18, "gap_max": 22.
"claim": text  the sentence of the brief this expectation proves (shown in the result).
Fields given to count_field and distinct must be dissected fields: tshark cannot print a byte slice
(tcp.payload[0:2]); check such values with one filter per value instead.
Any other key fails the check (a misspelt "windows" would otherwise be ignored).
Relations between fields are plain tshark filters: "ftp.active.cip != ip.src" (a PORT naming another
host), "ip.src != 10.0.0.2" (a spoofed source).
Prints PASS/FAIL lines, writes <dir>/out/verify.json, exits 0 when everything passed,
2 when a check failed, 1 on a usage or input error.
"""
import argparse
import json
import os
import subprocess
import sys

KEYS = {"filter", "min", "max", "endpoints", "count_field", "count_value", "window", "distinct",
        "gap_min", "gap_max", "claim"}
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


def matches(path, flt, field=None, value=None, distinct=None):
    """Frames matching flt: one (time, units, distinct values, source) row each. units is 1, or with
    field the occurrences of field[=value] in the frame."""
    # tshark prints a field named twice only once, so ask for each name once and look columns up by name
    wanted = ["frame.time_relative", field, distinct, "ip.src", "ipv6.src", "eth.src"]
    names = list(dict.fromkeys(f for f in wanted if f))
    rc, out, err = run(["tshark", "-n", "-r", path, "-Y", flt, "-T", "fields", "-E", "separator=|"]
                       + [x for f in names for x in ("-e", f)])
    if rc != 0:
        return None, err.strip().splitlines()[0] if err.strip() else f"tshark exit {rc}"
    col = {f: i for i, f in enumerate(names)}
    rows = []
    for r in out.splitlines():
        if not r.strip():
            continue
        p = (r.split("|") + [""] * len(names))[:len(names)]
        units = 1
        if field:
            vals = [v for v in p[col[field]].split(",") if v != ""]
            units = sum(1 for v in vals if value is None or v == str(value))
        dvals = {v for v in p[col[distinct]].split(",") if v != ""} if distinct else set()
        src = next((p[col[f]] for f in ("ip.src", "ipv6.src", "eth.src") if p[col[f]]), "")
        rows.append((float(p[col["frame.time_relative"]] or 0), units, dvals, src))
    return rows, None


def max_in_window(rows, width):
    """Most units in any window [t, t + width] that starts at a match."""
    best, j, acc = 0, 0, 0
    for i in range(len(rows)):
        while j < len(rows) and rows[j][0] - rows[i][0] <= width + 1e-9:
            acc += rows[j][1]
            j += 1
        best = max(best, acc)
        acc -= rows[i][1]
    return best


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
            flt = e.get("filter") if isinstance(e, dict) else None
            if not flt:
                res(False, f"expectation without a filter: {e}")
                continue
            unknown_keys = sorted(set(e) - KEYS)
            if unknown_keys:
                res(False, f"'{flt}': unknown key(s) {', '.join(unknown_keys)} (allowed: {', '.join(sorted(KEYS))})")
                continue
            if "window" in e and "distinct" in e:
                res(False, f"'{flt}': window and distinct measure different things; write two expectations")
                continue
            lo, hi, ep = int(e.get("min", 0 if "max" in e else 1)), e.get("max"), e.get("endpoints")
            cf, cv, win, dist = e.get("count_field"), e.get("count_value"), e.get("window"), e.get("distinct")
            gmin, gmax = e.get("gap_min"), e.get("gap_max")
            rows, terr = matches(path, flt, cf, cv, dist)
            if terr:
                res(False, f"tshark rejects filter '{flt}': {terr}")
                continue
            unit = f"{cf}{'=' + str(cv) if cv is not None else ''} occurrence(s)" if cf else "frame(s)"
            total = sum(r[1] for r in rows)
            rng = f"{lo}..{hi if hi is not None else '∞'}"
            if win is not None:
                n = max_in_window(rows, float(win))
                what = f"'{flt}' matches {total} {unit}, at most {n} in any {win} s window, expected {rng} in {win} s"
            elif dist:
                n = len(set().union(*(r[2] for r in rows))) if rows else 0
                what = f"'{flt}' matches {total} {unit} with {n} distinct {dist} value(s), expected {rng}"
            else:
                n = total
                what = f"'{flt}' matches {n} {unit}, expected {rng}"
            ok = n >= lo and (hi is None or n <= int(hi))
            if ep:
                nsrc = len({r[3] for r in rows if r[3]})
                ok = ok and nsrc >= int(ep)
                what += f"; {nsrc} distinct source(s), expected >= {ep}"
            if gmin is not None or gmax is not None:
                gaps = [b[0] - a[0] for a, b in zip(rows, rows[1:])]
                if not gaps:
                    ok = False
                    what += "; spacing needs 2 matches"
                else:
                    g_lo, g_hi = min(gaps), max(gaps)
                    ok = ok and (gmin is None or g_lo >= float(gmin)) and (gmax is None or g_hi <= float(gmax))
                    what += f"; spacing {g_lo:.3f}..{g_hi:.3f} s, expected {gmin if gmin is not None else 0}..{gmax if gmax is not None else '∞'} s"
            if e.get("claim"):
                what += f" [claim: {e['claim']}]"
            res(ok, what)
    out_path = os.path.join(a.lab, "out", "verify.json")
    try:
        merged = json.load(open(out_path)) if os.path.isfile(out_path) else {}
    except (OSError, json.JSONDecodeError):
        merged = {}
    merged.update(report)  # keep earlier traces' results: one file holds the whole mission's evidence
    try:
        with open(out_path + ".tmp", "w") as f:
            json.dump(merged, f, indent=1)
        os.replace(out_path + ".tmp", out_path)
    except OSError:
        pass
    print(f"RESULT {'PASS' if failed == 0 else 'FAIL'} ({failed} failed check(s))")
    sys.exit(0 if failed == 0 else 2)


if __name__ == "__main__":
    main()
