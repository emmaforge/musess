#!/usr/bin/env python3
"""Analyse a bulkclient -progress file into no-progress stall metrics.

Input: lines "ms_since_start cumulative_bytes" (first line = first byte).
Output (one line, space-separated k=v):
  ttfb_ms=<first-byte time> max_gap_ms=<longest interval with zero
  bytes delivered> gaps100=<# gaps >100ms> gaps200=<# gaps >200ms>
  gaps500=<# gaps >500ms> total_ms=<last sample> bytes=<final bytes>

A "gap" is the interval between two consecutive progress samples
with equal byte counts (progress is sampled every ~100 ms, so the
resolution floor is ~100 ms). The first sample (first byte) ends the
TTFB interval; the transfer's own start (0 ms, 0 bytes) to first byte
is the TTFB, not a stall.
"""
import sys

path = sys.argv[1]
samples = []
with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        ms, b = line.split()
        samples.append((int(ms), int(b)))

if not samples:
    print("ttfb_ms=NA max_gap_ms=NA gaps100=0 gaps200=0 gaps500=0 total_ms=0 bytes=0")
    sys.exit(0)

ttfb_ms = samples[0][0]
total_ms = samples[-1][0]
total_bytes = samples[-1][1]
max_gap = 0
gaps100 = gaps200 = gaps500 = 0
for (t0, b0), (t1, b1) in zip(samples, samples[1:]):
    if b1 == b0:
        gap = t1 - t0
        max_gap = max(max_gap, gap)
        if gap > 100:
            gaps100 += 1
        if gap > 200:
            gaps200 += 1
        if gap > 500:
            gaps500 += 1
print(f"ttfb_ms={ttfb_ms} max_gap_ms={max_gap} gaps100={gaps100} "
      f"gaps200={gaps200} gaps500={gaps500} total_ms={total_ms} bytes={total_bytes}")
