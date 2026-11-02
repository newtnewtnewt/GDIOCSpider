# GDIOCSpider — Demo Runbook (Thursday)

Two demos:

1. **CLI demo** — file inventory, IOC inventory, config abilities, keyword search.
2. **Agent Skill demo** — high-level prompting in Claude Code that drives the same CLI.

All commands are run **from the repo root** (`GDIOCSpider/`). The demo configs use
repo-relative paths (`gdiocspider/token.json`, `credentials.json`, `demo/keywords.txt`),
so there are no machine-specific absolute paths to edit.

**Offline fallbacks:** [`TRANSCRIPT.md`](TRANSCRIPT.md) holds real captured output of the
entire CLI demo, and [`TRANSCRIPT_SKILL.md`](TRANSCRIPT_SKILL.md) captures the agent-skill
demo (prompts → tool calls → answers) — use either if Drive/Wi-Fi is unavailable on stage.

---

## 0. Pre-flight (do this before you present)

```bash
# 1. Install the current build (includes the keyword + OAuth fixes)
pip install .

# 2. Confirm Google Drive auth is live. If the token is expired, this opens a
#    browser for consent and writes a fresh token.json. Do this NOW, not on stage.
gdiocspider list-files --config_file demo/configs/01_full_scan.json

# 3. Make an output dir (gitignored) for scan artifacts
mkdir -p demo/output
```

If the browser opens on the wrong profile, pick the right Google account on the
consent screen with **"Use another account"** — the browser profile doesn't matter,
the account does. For a headless machine add `--no-browser` and open the printed URL.

Expected inventory: **8 files** — 2 Google Sheets (`indicator_data`, `DELETE_ME`),
2 CSV, 1 Google Doc, 1 JSON, 1 Text, 1 Python.

---

## DEMO 1 — CLI

### 1a. File inventory (`list-files`)

> "Before crawling, see exactly what GDIOCSpider would touch — no downloads, no extraction."

```bash
gdiocspider list-files --config_file demo/configs/01_full_scan.json
```

**Expect:** a readable inventory grouped by category with the file names, ending
`Total: 8 file(s)` — no raw JSON blob. Talking point: this is the cheap pre-flight
you run before a full crawl to decide what to skip or target.

### 1b. IOC inventory (full `scan`)

> "Now crawl everything and extract indicators."

```bash
# Classic two-flag CSV (original tool) — readable progress + per-file totals
# print live on the console; the full table is saved to the CSV.
gdiocspider --config_file demo/configs/01_full_scan.json \
  --output_file demo/output/full.csv

# Same crawl as structured JSON. Results are written to --output_file; the crawl
# progress streams on stderr and nothing floods stdout. Summarize the file:
gdiocspider scan --config_file demo/configs/01_full_scan.json \
  --output_file demo/output/full.json --format json
python demo/summarize.py demo/output/full.json
```

**Expect:** **182 unique indicators across 8 files**, defanged on export
(`203[.]0[.]113[.]42`):

| Type | Count |
|---|--:|
| IPv4 | 62 |
| Domain Name | 46 |
| Email | 28 |
| File Name | 18 |
| MD5 | 14 |
| SHA256 | 10 |
| File Path | 4 |

Talking point: progress logs go to **stderr**, structured results to the
**`--output_file`** — the JSON array is *not* echoed to the terminal, so the file
is clean and the screen isn't flooded. `demo/summarize.py` prints the headline counts.

### 1c. Config abilities

**Targeting — `ONLY_SEARCH_FILES`** (`02_targeted.json` limits to `DELETE_ME.json` + `DELETE_ME.txt`):

```bash
gdiocspider scan --config_file demo/configs/02_targeted.json \
  --output_file demo/output/targeted.json --format json
python demo/summarize.py demo/output/targeted.json
```
**Expect:** only **2 files, 33 indicators**. Same Drive, scoped crawl.

**Noise reduction — `SEARCH_EXCLUSION_LIST`** (`03_exclude_types.json` drops `File Name` + `File Path`):

```bash
gdiocspider scan --config_file demo/configs/03_exclude_types.json \
  --output_file demo/output/network_only.json --format json
python demo/summarize.py demo/output/network_only.json
```
**Expect:** **160 indicators** (the 22 File Name/Path rows gone) — just the
network/host IOCs an analyst usually wants first.

**Defanging — `DEFANG_BEFORE_EXPORT`**: `01` has it `true` (`8[.]8[.]8[.]8`). Point out
the exported values are safe to paste into tickets/chat without creating live links.

**Strict vs. loose typing — `IOC_TYPER_STRICT_MODE`**: shown live in 1d below with the
`type` subcommand.

### 1d. Keyword search (`KEYWORD_FILEPATHS_TO_USE`)

> "Beyond structured IOCs, hunt for arbitrary terms — project names, 'Malware', anything in `demo/keywords.txt`."

```bash
gdiocspider scan --config_file demo/configs/04_keywords.json \
  --output_file demo/output/keywords.json --format json
python demo/summarize.py demo/output/keywords.json

# To show the actual words that matched, grep the live progress (on stderr):
gdiocspider scan --config_file demo/configs/04_keywords.json \
  --output_file demo/output/keywords.json --format json 2>&1 >/dev/null \
  | grep "Type: Keyword"
```
**Expect:** Keyword type now appears — **208 total indicators, 26 of them `Keyword`**
(e.g. `Malware`, `traffic`, `detected`, `hash`, `email`). The keyword list is
`demo/keywords.txt`; edit it live to show a new term getting picked up.

**Bonus — IOCFlagger `type` (no Drive, instant), great for strict vs. loose:**

```bash
gdiocspider type --value "8.8.8.8:443"              # strict  -> Unknown
gdiocspider type --value "8.8.8.8:443" --no-strict  # loose   -> IPv4
gdiocspider type --value "d41d8cd98f00b204e9800998ecf8427e"  # -> MD5
```

---

## DEMO 2 — Agent Skill in Claude Code

> Point: a user doesn't memorize flags. They ask in plain language; the skill
> picks the right subcommand, writes config, runs it, and summarizes.

Open Claude Code in the repo. The `gdiocspider` skill is already installed under
`.claude/skills/`. Try these **high-level, analytical prompts** — each asks the
skill to crawl *and reason over the result*. Full answers with real figures are in
[`TRANSCRIPT_SKILL.md`](TRANSCRIPT_SKILL.md).

1. **Rank sources & spot prior reports (→ `scan` + ranking)**
   > "Crawl my whole Drive, rank the files by how many unique IOCs each contributes,
   > and for the biggest real source break down whether it's mostly network or
   > file-based. Flag anything that's actually a previous report, not source data.
   > Keep the `old_school_stuff` folder excluded — there's too much content in it."

   Payoff: the agent catches `indicator_data` / `indicator_data.csv` as a
   re-ingested report and names `DELETE_ME.csv` (32, all network) as the real top source.

2. **Overlap / dedupe (→ `scan` + set diff)**
   > "Do my two Google Sheets overlap or are they independent? Which indicators do
   > they share, and which are unique to each? Keep the `old_school_stuff` folder
   > excluded — there's too much content in it."

   Payoff: proves `DELETE_ME` is fully contained in `indicator_data` (0 unique).

3. **Cross-file pivots (→ `scan` + value→files index)**
   > "Which domains and emails show up in more than one file? Ignore my prior-report
   > files — the repeats in the real source data are my best pivot points. Keep the
   > `old_school_stuff` folder excluded — there's too much content in it."

   Payoff: ranks `phishing@badguys[.]com`, `dangerous-link[.]org`, `test@malicious[.]net`
   (3 real files each) as top pivots.

4. **Keyword hunt with context (→ keyword config + `scan` + correlation)**
   > "Turn on keyword hunting for `Malware` and `traffic`, and tell me which files
   > mention them and what other IOCs sit alongside — I want context, not a count.
   > Keep the `old_school_stuff` folder excluded — there's too much content in it."

   Payoff: `Malware` in 2 files, `traffic` in 4; both land together in
   `DELETE_ME_GDOCS` and `DELETE_ME.txt` next to network IOCs + a hash.

5. **Targeted comparison (→ `ONLY_SEARCH_FILES` + `scan`)**
   > "Scan only my JSON and text files and compare them on network IOCs and hashes —
   > which is the richer artifact to triage first? Keep the `old_school_stuff` folder
   > excluded — there's too much content in it."

   Payoff: `DELETE_ME.json` wins (net 10 / hash 5 vs. 8 / 3).

**Talking points while it runs:**
- The skill reads `references/cli.md` / `references/config.md` to pick flags — the
  same knowledge a new teammate would need, encoded once.
- It follows the skill's rules: progress on stderr, summarize don't dump, never
  print secrets from `token.json`, don't start an unattended OAuth flow.
- Same engine as Demo 1 — the agent is just a smart front-end over the CLI.

---

## Reset between runs

```bash
rm -f demo/output/*
```

Nothing else to clean up — scans download to a temp dumpster and delete as they go.
