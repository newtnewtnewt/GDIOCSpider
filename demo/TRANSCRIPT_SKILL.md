# GDIOCSpider — Agent Skill Demo Transcript (captured dry run)

Captured on 2026-11-01 against a live Google Drive. This shows the five
high-level prompts from the runbook and the tool calls the `gdiocspider` skill
makes in Claude Code, with real command output (trimmed) and the answer.

> The skill auto-loads in a fresh Claude Code session (it lives in
> `.claude/skills/gdiocspider/`). If you just installed it, **restart Claude Code**
> so it registers. The skill routes each request: a pasted indicator → `type`
> (no Drive); a Drive hunt → `config` + `list-files` + `scan`, then a summary.

---

## Prompt 1 — single indicator

**💬 You:** "Is `203.0.113.42` an IOC, and what type?"

**🔧 Skill routes to `type` (no Drive crawl):**

```console
$ gdiocspider type --value "203.0.113.42"
{
  "ioc_value": "203[.]0[.]113[.]42",
  "ioc_type": "IPv4"
}
```

**🤖 Claude:** Yes — `203.0.113.42` classifies as an **IPv4** address. It's shown
defanged (`203[.]0[.]113[.]42`) so it's safe to paste into tickets. This is a
pure classification; I didn't touch your Drive.

---

## Prompt 2 — pasted log line

**💬 You:** "Pull any indicators out of this line: `Malware traffic detected from 203.0.113.42 via noxious@phishingsite.net`"

**🔧 Skill uses `type --no-strict` (searches within text). A single call returns
the first match, so I classify each token to surface everything:**

```console
$ gdiocspider type --value "Malware traffic detected from 203.0.113.42 via noxious@phishingsite.net" --no-strict
{ "ioc_value": "203[.]0[.]113[.]42", "ioc_type": "IPv4" }

$ # per-token pass to catch all IOCs:
Malware                   -> Unknown
traffic                   -> Unknown
detected                  -> Unknown
203.0.113.42              -> IPv4
noxious@phishingsite.net  -> Email
```

**🤖 Claude:** Two indicators in that line:
- **IPv4** — `203[.]0[.]113[.]42`
- **Email** — `noxious@phishingsite[.]net`

"Malware/traffic/detected" are plain prose, not structured IOCs, so the typer
leaves them `Unknown` (they'd only register if you supplied a keyword list).

---

## Prompt 3 — inventory first

**💬 You:** "What files in my Google Drive would GDIOCSpider scan? Don't extract anything yet."

**🔧 Skill routes to `list-files` (auth + inventory, no downloads):**

```console
$ gdiocspider list-files --config_file demo/configs/01_full_scan.json
  total 8
    Google Sheets 2
    CSV File      2
    Google Docs   1
    JSON File     1
    Text File     1
    Python Script 1
```

**🤖 Claude:** GDIOCSpider would scan **8 files**: 2 Google Sheets
(`indicator_data`, `DELETE_ME`), 2 CSVs (`indicator_data.csv`, `DELETE_ME.csv`),
1 Google Doc (`DELETE_ME_GDOCS`), 1 JSON (`DELETE_ME.json`), 1 text file
(`DELETE_ME.txt`), and 1 Python script (`DELETE_ME.py`). The `old_school_stuff`
folder is skipped per the ignore list. Nothing was downloaded or extracted.

---

## Prompt 4 — full hunt + judgment

**💬 You:** "Hunt for IOCs across my Drive and tell me the top indicator types and which file has the most hits. Call out anything that's probably a false positive."

**🔧 Skill routes to `scan`, then reasons over the result:**

```console
$ gdiocspider scan --config_file demo/configs/01_full_scan.json \
    --output_file demo/output/full.json --format json
  (progress on stderr; 182 indicators across 8 files)

TYPES: IPv4 62, Domain Name 46, Email 28, File Name 18, MD5 14, SHA256 10, File Path 4
FILES (name, unique, hits):
  indicator_data          48  214
  indicator_data.csv      48  214
  DELETE_ME.csv           32   32
  DELETE_ME.json          21   21
  DELETE_ME_GDOCS         14   17
  DELETE_ME.txt           12   12
  DELETE_ME                6    6
  DELETE_ME.py            1    1
```

**🤖 Claude:** **182 unique indicators across all 8 files.** Top types: **IPv4 (62),
Domain Name (46), Email (28)** — a network-heavy set — then File Name 18, MD5 14,
SHA256 10, File Path 4.

Most hits: **`indicator_data` and `indicator_data.csv`** (214 each).

Likely false positives to flag:
- **`indicator_data` / `indicator_data.csv` are a previous GDIOCSpider *output*
  file** re-ingested as input — that's why their counts dominate and mirror each
  other. In a real hunt I'd exclude prior reports from the scan scope.
- The **File Name** type (18) is the noisiest category — generic names like
  `invoice.docx` / `document.pdf` match but rarely mean anything on their own.
- Private/reserved IPs (`192.168.*`, `10.0.*`, `127.0.0.1`) are extracted but
  aren't threat indicators by themselves.

---

## Prompt 5 — targeted, comparative

**💬 You:** "Only scan the JSON and text files in my Drive, and compare how many network IOCs each one has."

**🔧 Skill writes `ONLY_SEARCH_FILES` config, scans, compares:**

```console
$ gdiocspider scan --config_file demo/configs/02_targeted.json \
    --output_file demo/output/targeted.json --format json
  DELETE_ME.json   network=10 (IPv4 6, Domain 4)
  DELETE_ME.txt    network=8  (IPv4 5, Domain 3)
```

**🤖 Claude:** Scanning only the two files: **`DELETE_ME.json` has more network
IOCs — 10 (6 IPv4 + 4 domains)** vs. **`DELETE_ME.txt` with 8 (5 IPv4 + 3
domains)**. The JSON also carries more hashes (3 MD5 + 2 SHA256) than the text
file (2 MD5 + 1 SHA256), so it's the richer artifact overall.

---

## Why this lands

- The user never typed a flag or a MIME type — the skill translated intent into
  the right subcommand and config each time.
- It distinguishes "classify this string" (no Drive) from "hunt my Drive" on its
  own.
- On the full hunt it **reasons** — surfacing the self-referential output file
  and the noisy File Name type — instead of dumping 182 rows.
- Same engine as the CLI demo; the agent is a natural-language front-end.
