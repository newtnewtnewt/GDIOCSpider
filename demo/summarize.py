#!/usr/bin/env python3
"""Summarize a GDIOCSpider JSON scan result.

Reads the nested scan JSON (a list of {file_metadata, all_indicators}) from a
file path, or from stdin when the argument is "-". Prints a compact type table
and the highest-hit files instead of echoing the whole array -- so a live demo
shows the headline numbers, not a flood of JSON.

Usage:
  gdiocspider scan ... --format json --output_file out.json >/dev/null
  python demo/summarize.py out.json

  # or pipe directly (progress still shows on stderr):
  gdiocspider scan ... --format json --output_file out.json | python demo/summarize.py -
"""
import collections
import json
import sys

src = sys.argv[1] if len(sys.argv) > 1 else "-"
raw = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
data = json.loads(raw)

by_type = collections.Counter()
files = []
for rec in data:
    inds = rec.get("all_indicators", []) or []
    files.append((rec.get("file_metadata", {}).get("name", "?"), len(inds)))
    for i in inds:
        by_type[i.get("type")] += 1

total = sum(by_type.values())
with_iocs = sum(1 for _, n in files if n)
print(f"{total} unique indicators across {with_iocs} file(s)\n")

if by_type:
    width = max(len(t or "") for t in by_type)
    print("IOC type".ljust(width), "count")
    for t, c in by_type.most_common():
        print(f"{(t or '').ljust(width)}  {c}")

print("\nHighest-hit files:")
for name, n in sorted(files, key=lambda x: -x[1])[:5]:
    print(f"  {name}: {n}")
