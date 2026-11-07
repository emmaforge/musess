#!/usr/bin/env python3
"""Analyse H2/mux record-shape captures.

Inputs: JSONL files from record-tap.py (TLS records) and helper
h2tap (H2 frames). Prints, per file:
  - TLS records (type 23, application_data, both directions):
    count, size mean/median/p95/max, and inter-arrival median/p95
  - H2 frames: per-type counts and DATA frame size distribution
    (mean/median/p95/max + size buckets)
Usage: h2-analyze.py <label=file> ...
"""
import json
import statistics
import sys


def pct(vals, p):
    if not vals:
        return 0
    s = sorted(vals)
    i = min(len(s) - 1, int(p / 100 * len(s)))
    return s[i]


def analyse_records(path):
    recs = []
    with open(path) as f:
        for line in f:
            recs.append(json.loads(line))
    app = [r for r in recs if r["type"] == 23]
    out = {}
    for direction in ("c2s", "s2c"):
        d = [r for r in app if r["dir"] == direction]
        sizes = [r["len"] for r in d]
        times = [r["t_ms"] for r in d]
        gaps = [b - a for a, b in zip(times, times[1:])]
        out[direction] = {
            "n": len(d),
            "size_mean": round(statistics.mean(sizes), 1) if sizes else 0,
            "size_median": statistics.median(sizes) if sizes else 0,
            "size_p95": pct(sizes, 95),
            "size_max": max(sizes) if sizes else 0,
            "gap_median_ms": statistics.median(gaps) if gaps else 0,
            "gap_p95_ms": pct(gaps, 95),
        }
    hs = [r for r in recs if r["type"] == 22]
    out["handshake_records"] = len(hs)
    return out


def analyse_frames(path):
    frames = []
    with open(path) as f:
        for line in f:
            frames.append(json.loads(line))
    by_type = {}
    data_sizes = []
    for fr in frames:
        by_type.setdefault(fr["type"], []).append(fr["len"])
        if fr["type"] == "DATA":
            data_sizes.append(fr["len"])
    buckets = {"<=1K": 0, "<=4K": 0, "<=16K": 0, ">16K": 0}
    for n in data_sizes:
        if n <= 1024:
            buckets["<=1K"] += 1
        elif n <= 4096:
            buckets["<=4K"] += 1
        elif n <= 16384:
            buckets["<=16K"] += 1
        else:
            buckets[">16K"] += 1
    return {
        "types": {k: len(v) for k, v in sorted(by_type.items())},
        "data_n": len(data_sizes),
        "data_mean": round(statistics.mean(data_sizes), 1) if data_sizes else 0,
        "data_median": statistics.median(data_sizes) if data_sizes else 0,
        "data_p95": pct(data_sizes, 95),
        "data_max": max(data_sizes) if data_sizes else 0,
        "data_buckets": buckets,
    }


for arg in sys.argv[1:]:
    label, path = arg.split("=", 1)
    try:
        with open(path) as f:
            first = f.readline()
        if not first.strip():
            print(f"{label}: empty")
            continue
        kind = json.loads(first)
        if "type" in kind and isinstance(kind["type"], int):
            res = analyse_records(path)
            print(f"== {label} (TLS records) ==")
            for direction in ("c2s", "s2c"):
                d = res[direction]
                print(f"  {direction} appdata: n={d['n']} size mean={d['size_mean']} "
                      f"median={d['size_median']} p95={d['size_p95']} max={d['size_max']} "
                      f"gap median={d['gap_median_ms']}ms p95={d['gap_p95_ms']}ms")
            print(f"  handshake records: {res['handshake_records']}")
        else:
            res = analyse_frames(path)
            print(f"== {label} (H2 frames) ==")
            print(f"  types: {res['types']}")
            print(f"  DATA: n={res['data_n']} mean={res['data_mean']} median={res['data_median']} "
                  f"p95={res['data_p95']} max={res['data_max']} buckets={res['data_buckets']}")
    except FileNotFoundError:
        print(f"{label}: MISSING {path}")
