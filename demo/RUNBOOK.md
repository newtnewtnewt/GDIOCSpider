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

**Expect:** JSON grouped by category, `"total": 8`. Talking point: this is the
cheap pre-flight you run before a full crawl to decide what to skip or target.

### 1b. IOC inventory (full `scan`)

> "Now crawl everything and extract indicators."

```bash
# Classic two-flag CSV (original tool) — readable progress + per-file totals
# print live on the console; the full table is saved to the CSV.
gdiocspider --config_file demo/configs/01_full_scan.json \
  --output_file demo/output/full.csv

# Same crawl as structured JSON. --format json echoes the whole array to stdout,
# so pipe it into the summarizer (the array lands in demo/output/full.json via
# --output_file; the live crawl progress still shows on stderr).
gdiocspider scan --config_file demo/configs/01_full_scan.json \
  --output_file demo/output/full.json --format json | python demo/summarize.py -
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

Talking point: progress logs go to **stderr**, structured results to **stdout/`--output_file`**.
Don't echo the raw JSON on stage — pipe it to `demo/summarize.py` (or redirect to a
file) so the terminal shows the headline counts, not 182 records.

### 1c. Config abilities

**Targeting — `ONLY_SEARCH_FILES`** (`02_targeted.json` limits to `DELETE_ME.json` + `DELETE_ME.txt`):

```bash
gdiocspider scan --config_file demo/configs/02_targeted.json \
  --output_file demo/output/targeted.json --format json | python demo/summarize.py -
```
**Expect:** only **2 files, 33 indicators**. Same Drive, scoped crawl.

**Noise reduction — `SEARCH_EXCLUSION_LIST`** (`03_exclude_types.json` drops `File Name` + `File Path`):

```bash
gdiocspider scan --config_file demo/configs/03_exclude_types.json \
  --output_file demo/output/network_only.json --format json | python demo/summarize.py -
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
  --output_file demo/output/keywords.json --format json | python demo/summarize.py -

# To show the actual words that matched, grep the live progress instead:
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
`.claude/skills/`. Try these **high-level prompts** (each maps to tool calls the
audience can watch):

1. **Single indicator (→ `type`)**
   > "Is `203.0.113.42` an IOC, and what type?"

   Shows the skill choosing `type` and *not* crawling Drive.

2. **Pasted log line (→ `type --no-strict`)**
   > "Pull any indicators out of this line: `Malware traffic detected from 203.0.113.42 via noxious@phishingsite.net`"

   Shows loose mode extracting the IP/email from inside prose.

3. **Inventory first (→ `list-files`)**
   > "What files in my Google Drive would GDIOCSpider scan? Don't extract anything yet."

   Shows the skill running the cheap inventory and reading it back.

4. **Full hunt + judgment (→ config + `scan` + summary)**
   > "Hunt for IOCs across my Drive and tell me the top indicator types and which
   > file has the most hits. Call out anything that's probably a false positive."

   Shows the skill scanning and then *reasoning* over the result — e.g. flagging
   the `File Name` type as noisy — instead of dumping every row.

5. **Targeted, comparative (→ `ONLY_SEARCH_FILES` + `scan`)**
   > "Only scan the JSON and text files in my Drive, and compare how many network
   > IOCs each one has."

   Shows the skill translating intent into `ONLY_SEARCH_FILES` config.

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
