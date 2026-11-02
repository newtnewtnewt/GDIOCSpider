# GDIOCSpider — Agent Skill Demo Transcript (captured dry run)

Captured on 2026-11-01 against a live Google Drive. Five high-level, analytical
prompts and the tool calls the `gdiocspider` skill makes in Claude Code — each
one asks the agent to crawl, then *reason* over the result, not just run a
command. All figures are real.

> The skill auto-loads in a fresh Claude Code session (it lives in
> `.claude/skills/gdiocspider/`). If you just installed it, **restart Claude Code**
> so it registers. In JSON mode `scan` writes results to `--output_file` (it does
> not flood stdout); the agent reads that file to answer.

---

## Prompt 1 — rank sources & spot prior reports

**💬 You:** "Crawl my whole Drive, rank the files by how many unique IOCs each
contributes, and for the biggest real source break down whether it's mostly
network or file-based. Flag anything that's actually a previous report rather
than source data."

**🔧 Skill routes to a full `scan`, then reasons over `demo/output/full.json`:**

```console
$ gdiocspider scan --config_file demo/configs/01_full_scan.json \
    --output_file demo/output/full.json --format json
  ... crawl progress on stderr ...
  Wrote 8 file record(s) to demo/output/full.json
```

**🤖 Claude:** Ranked by unique indicators:

| File | Unique | Note |
|---|--:|---|
| `indicator_data` | 48 | ⚠ prior report |
| `indicator_data.csv` | 48 | ⚠ prior report (identical set) |
| `DELETE_ME.csv` | 32 | real source |
| `DELETE_ME.json` | 21 | real source |
| `DELETE_ME_GDOCS` | 14 | real source |
| `DELETE_ME.txt` | 12 | real source |
| `DELETE_ME` | 6 | real source |
| `DELETE_ME.py` | 1 | real source |

**The top two are a trap** — `indicator_data` and `indicator_data.csv` hold the
*exact same* 48 indicators and contain report-schema filenames (`DELETE_ME.csv`
appearing 64×), so they're a previous GDIOCSpider export re-ingested, not source
data. Excluding them, your biggest real source is **`DELETE_ME.csv` (32 unique)**,
and it's almost entirely **network/host**: 21 network (14 IPv4 + 7 domains) plus
6 emails and 5 hashes, with **zero** filename/path noise. That's the file to
triage first.

---

## Prompt 2 — are the two sheets independent?

**💬 You:** "Do my two Google Sheets (`indicator_data` and `DELETE_ME`) overlap
or are they independent? Tell me which indicators they share and which are unique
to each."

**🔧 Skill `scan`s, then diffs the two sheets' indicator sets:**

```console
$ gdiocspider scan --config_file demo/configs/01_full_scan.json \
    --output_file demo/output/full.json --format json
  Wrote 8 file record(s) to demo/output/full.json
```

**🤖 Claude:** They're **not independent** — `DELETE_ME` is fully contained in
`indicator_data`. All 6 of `DELETE_ME`'s indicators (`192.168.1.1`, `fake.sh`,
`fake.py`, `www.bull.com`, `www.fake.com`, `www.thisaintreal.com`) also appear in
`indicator_data`; **nothing is unique to `DELETE_ME`**, while `indicator_data` has
42 others on top. So `indicator_data` is an aggregate report that already absorbed
`DELETE_ME`'s findings — treat `DELETE_ME` as redundant and dedupe against the
report rather than counting both.

---

## Prompt 3 — cross-file pivot points

**💬 You:** "Which domains and emails show up in more than one file? Ignore my
prior-report files — the repeats across the *real* source files are my best pivot
points."

**🔧 Skill `scan`s, builds a value→files index, drops the report files:**

```console
$ gdiocspider scan --config_file demo/configs/01_full_scan.json \
    --output_file demo/output/full.json --format json
  Wrote 8 file record(s) to demo/output/full.json
```

**🤖 Claude:** Excluding `indicator_data` / `indicator_data.csv`, the indicators
that recur across the most *real* source files — your strongest pivots:

| Indicator | Real source files |
|---|--:|
| `phishing@badguys[.]com` | 3 (csv, txt, gdocs) |
| `dangerous-link[.]org` | 3 (csv, txt, gdocs) |
| `test@malicious[.]net` | 3 (csv, json, gdocs) |
| `bad-actor[.]com`, `phishing@evil[.]com`, `suspicious-site[.]org`, `www.malicious-site[.]com`, `innocent@legit[.]com`, `www.example-safe[.]com`, `safeuser@example[.]com` | 2 each |

The top three appear in three independent files apiece — if I were pivoting, I'd
start with `phishing@badguys[.]com` and `dangerous-link[.]org`.

---

## Prompt 4 — keyword hunt with context

**💬 You:** "Turn on keyword hunting for `Malware` and `traffic`, and tell me
which files mention them and what other IOCs sit alongside — I want the context,
not just a hit count."

**🔧 Skill switches to the keyword config (`Keyword` enabled + `demo/keywords.txt`),
`scan`s, then correlates keyword hits with co-located IOCs:**

```console
$ gdiocspider scan --config_file demo/configs/04_keywords.json \
    --output_file demo/output/keywords.json --format json
  Wrote 8 file record(s) to demo/output/keywords.json
```

**🤖 Claude:**
- **`Malware`** — 2 files. `DELETE_ME_GDOCS` (alongside 5 IPv4, 4 domains, 3
  emails, 1 SHA256) and `DELETE_ME.txt` (5 IPv4, 3 domains, 2 MD5, 1 SHA256).
- **`traffic`** — 4 files: `DELETE_ME.csv`, `DELETE_ME_GDOCS`, `DELETE_ME.json`,
  `DELETE_ME.txt`.

Both terms land together in **`DELETE_ME_GDOCS` and `DELETE_ME.txt`**, each next
to a cluster of network IOCs and a hash — those two read like incident narratives,
so they're the artifacts to open first for context.

---

## Prompt 5 — structured vs. unstructured richness

**💬 You:** "Scan only my JSON and text files and compare them on network IOCs and
hashes — which is the richer artifact to triage first?"

**🔧 Skill writes an `ONLY_SEARCH_FILES` config, `scan`s, compares:**

```console
$ gdiocspider scan --config_file demo/configs/02_targeted.json \
    --output_file demo/output/targeted.json --format json
  Wrote 2 file record(s) to demo/output/targeted.json
```

**🤖 Claude:** **`DELETE_ME.json` is the richer artifact.** Network IOCs: **10**
(6 IPv4 + 4 domains) vs. the text file's **8** (5 IPv4 + 3 domains). Hashes: **5**
(3 MD5 + 2 SHA256) vs. **3** (2 MD5 + 1 SHA256). The JSON carries more of both, so
triage it before `DELETE_ME.txt`.

---

## Why this lands

- Every prompt is a real analyst question — rank, dedupe, pivot, correlate,
  compare — not a flag lookup. The user states intent; the skill picks the config
  and subcommand and does the crawl.
- The agent **reasons over the result**: it catches the two `indicator_data`
  files as re-ingested reports (Prompts 1–3), proves one sheet is a subset of the
  other (Prompt 2), and ranks pivots by cross-file recurrence (Prompt 3).
- Same engine as the CLI demo — the agent is just a natural-language analyst on
  top of the same `scan`.
