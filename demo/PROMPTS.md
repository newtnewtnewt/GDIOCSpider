# GDIOCSpider — Demo Prompts & Commands (paste-ready)

Everything below is copy-paste ready. Run all commands **from the repo root**
(`GDIOCSpider/`). See [`RUNBOOK.md`](RUNBOOK.md) for the full script, expected
numbers, and talking points; [`TRANSCRIPT.md`](TRANSCRIPT.md) /
[`TRANSCRIPT_SKILL.md`](TRANSCRIPT_SKILL.md) are offline fallbacks.

---

## Pre-flight (once, before presenting)

```bash
pip install .
gdiocspider list-files --config_file demo/configs/01_full_scan.json   # triggers auth if token expired
mkdir -p demo/output
```

> Tip: add the allow rule `Bash(gdiocspider:*)` via `/permissions` so the agent
> demo doesn't prompt for every CLI call on stage.

---

## DEMO 1 — the 5 CLI commands

### 1. File inventory (no downloads, no extraction)
```bash
gdiocspider list-files --config_file demo/configs/01_full_scan.json
```
Expect: a readable inventory by category with file names, ending `Total: 8 file(s)`.

### 2. Full scan — all IOCs
```bash
gdiocspider scan --config_file demo/configs/01_full_scan.json --output_file demo/output/full.json --format json
python demo/summarize.py demo/output/full.json
```
Expect: **182 unique indicators across 8 files** (IPv4 62, Domain 46, Email 28,
File Name 18, MD5 14, SHA256 10, File Path 4).

Classic CSV variant (live per-file totals on console):
```bash
gdiocspider --config_file demo/configs/01_full_scan.json --output_file demo/output/full.csv
```

### 3. Targeted scan — `ONLY_SEARCH_FILES`
```bash
gdiocspider scan --config_file demo/configs/02_targeted.json --output_file demo/output/targeted.json --format json
python demo/summarize.py demo/output/targeted.json
```
Expect: **2 files, 33 indicators**.

### 4. Noise reduction — `SEARCH_EXCLUSION_LIST` (drops File Name + File Path)
```bash
gdiocspider scan --config_file demo/configs/03_exclude_types.json --output_file demo/output/network_only.json --format json
python demo/summarize.py demo/output/network_only.json
```
Expect: **160 indicators** (network/host IOCs only).

### 5. Keyword hunt — `KEYWORD_FILEPATHS_TO_USE`
```bash
gdiocspider scan --config_file demo/configs/04_keywords.json --output_file demo/output/keywords.json --format json
python demo/summarize.py demo/output/keywords.json

# show the actual matched words (progress is on stderr):
gdiocspider scan --config_file demo/configs/04_keywords.json --output_file demo/output/keywords.json --format json 2>&1 >/dev/null | grep "Type: Keyword"
```
Expect: **208 total, 26 `Keyword`** (e.g. `Malware`, `traffic`, `detected`, `hash`, `email`).

### Bonus — `type` (no Drive, instant; strict vs. loose)
```bash
gdiocspider type --value "8.8.8.8:443"              # strict  -> Unknown
gdiocspider type --value "8.8.8.8:443" --no-strict  # loose   -> IPv4
gdiocspider type --value "d41d8cd98f00b204e9800998ecf8427e"  # -> MD5
```

---

## DEMO 2 — the 5 Agent-Skill prompts

Paste these into a **fresh** Claude Code session in the repo (restart so the
`gdiocspider` skill registers). Each asks the agent to crawl *and reason* over the
result. Real answers are in [`TRANSCRIPT_SKILL.md`](TRANSCRIPT_SKILL.md).

**1. Rank sources & spot prior reports**
> Crawl my whole Drive, rank the files by how many unique IOCs each contributes, and for the biggest real source break down whether it's mostly network or file-based. Flag anything that's actually a previous report, not source data. Keep the `old_school_stuff` folder excluded — there's too much content in it.

**2. Overlap / dedupe**
> Do my two Google Sheets overlap or are they independent? Which indicators do they share, and which are unique to each? Keep the `old_school_stuff` folder excluded — there's too much content in it.

**3. Cross-file pivots**
> Which domains and emails show up in more than one file? Ignore my prior-report files — the repeats in the real source data are my best pivot points. Keep the `old_school_stuff` folder excluded — there's too much content in it.

**4. Keyword hunt with context**
> Turn on keyword hunting for `Malware` and `traffic`, and tell me which files mention them and what other IOCs sit alongside — I want context, not a count. Keep the `old_school_stuff` folder excluded — there's too much content in it.

**5. Targeted comparison (structured vs. unstructured)**
> Scan only my JSON and text files and compare them on network IOCs and hashes — which is the richer artifact to triage first? Keep the `old_school_stuff` folder excluded — there's too much content in it.

---

## Reset between runs
```bash
rm -f demo/output/*
```
