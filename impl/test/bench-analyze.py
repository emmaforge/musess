#!/usr/bin/env python3
"""Analyse bench-mux.sh results.txt into medians and musess/SS2022
goodput ratios.

Usage: bench-analyze.py <results.txt>
Prints:
  - median seconds/mbps per (setting, leg, workload)
  - musess/SS2022 goodput ratio per (setting, workload-class) for
    stock / mux / muxfec, with the gap to 1.0
  - stall summary per (setting, leg) from the loss legs
Workload classes: ttfb (1 MiB bulk), ttfb_https, bulk32, bulk256,
seq10 (warm), seq10cold, mixed. For time-based workloads (ttfb*)
the ratio is expressed as speedup (ss_seconds / leg_seconds);
for goodput workloads it is leg_mbps / ss_mbps.
"""
import statistics
import sys
from collections import defaultdict

WORKLOADS = {
    "bulk1048576": "ttfb",
    "bulk33554432": "bulk32",
    "bulk268435456": "bulk256",
    "seq10": "seq10",
    "seq10cold": "seq10cold",
    "mixed": "mixed",
    "ttfb_https": "ttfb_https",
}

rows = defaultdict(list)   # (setting, leg, workload) -> [seconds]
mbps = defaultdict(list)   # (setting, leg, workload) -> [mbps]
stalls = defaultdict(list)  # (setting, leg) -> dicts
sanity_fail = []


def parse_kv(line):
    d = {}
    for tok in line.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            d[k] = v
    return d


with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line or "FAILED" in line or "stalled=yes" in line:
            if "SHIM_SANITY_FAIL" in line:
                sanity_fail.append(line)
            continue
        d = parse_kv(line)
        if "stall" in line and "ttfb_ms" in d:
            stalls[(d.get("setting"), d.get("leg"))].append(d)
            continue
        if not {"setting", "leg", "workload", "seconds"} <= set(d):
            continue
        wl = WORKLOADS.get(d["workload"], d["workload"])
        key = (d["setting"], d["leg"], wl)
        rows[key].append(float(d["seconds"]))
        if "mbps" in d:
            mbps[key].append(float(d["mbps"]))


def med(vals):
    return statistics.median(vals) if vals else float("nan")


settings = sorted({k[0] for k in rows}, key=lambda s: ["none", "delay25", "delay100", "loss25", "loss100"].index(s) if s in ["none", "delay25", "delay100", "loss25", "loss100"] else 99)
legs = ["direct", "ss2022", "stock", "mux", "muxfec"]
workloads = ["ttfb", "ttfb_https", "bulk32", "bulk256", "seq10", "seq10cold", "mixed"]

print("## medians (seconds; mbps in parens)")
print("| setting | workload | " + " | ".join(legs) + " |")
print("|---|---|" + "---|" * len(legs))
for s in settings:
    for w in workloads:
        cells = []
        for leg in legs:
            key = (s, leg, w)
            if key in rows:
                if key in mbps:
                    cells.append(f"{med(rows[key]):.3f} ({med(mbps[key]):.0f})")
                else:
                    cells.append(f"{med(rows[key]):.3f}")
            else:
                cells.append("—")
        if any(c != "—" for c in cells):
            print(f"| {s} | {w} | " + " | ".join(cells) + " |")

print()
print("## musess/SS2022 ratio (goodput legs: leg_mbps/ss_mbps; time legs: ss_s/leg_s; 1.0 = parity)")
print("| setting | workload | stock | mux | muxfec |")
print("|---|---|---|---|---|")
for s in settings:
    for w in workloads:
        ss_key = (s, "ss2022", w)
        if ss_key not in rows:
            continue
        cells = []
        for leg in ["stock", "mux", "muxfec"]:
            key = (s, leg, w)
            if key not in rows:
                cells.append("—")
                continue
            if w in ("ttfb", "ttfb_https"):
                r = med(rows[ss_key]) / med(rows[key])
            else:
                r = med(mbps[key]) / med(mbps[ss_key])
            cells.append(f"{r:.2f} (short {1.0 - r:.2f})" if r < 1 else f"{r:.2f}")
        print(f"| {s} | {w} | " + " | ".join(cells) + " |")

print()
print("## no-progress stalls (loss legs; median over reps)")
print("| setting | leg | ttfb_ms | max_gap_ms | gaps>200ms | gaps>500ms |")
print("|---|---|---|---|---|---|")
for (s, leg), ds in sorted(stalls.items()):
    def m(k):
        return med([float(d[k]) for d in ds])
    print(f"| {s} | {leg} | {m('ttfb_ms'):.0f} | {m('max_gap_ms'):.0f} | {m('gaps200'):.0f} | {m('gaps500'):.0f} |")

if sanity_fail:
    print()
    print("## SHIM SANITY FAILURES (numbers void)")
    for line in sanity_fail:
        print(f"- {line}")
