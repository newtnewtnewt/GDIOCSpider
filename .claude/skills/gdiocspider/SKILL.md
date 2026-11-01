---
name: gdiocspider
description: Extract and classify IOCs from Google Drive with GDIOCSpider, or type a single hash/IP/domain/email string. Use when hunting IOCs in GDrive, writing config.json from a natural-language scan request, listing Drive files before a crawl, or classifying pasted indicators.
license: MIT
compatibility: Requires Python 3, the GDIOCSpider package installed (`pip install .` from the repo), Google Drive API credentials (credentials.json and token.json), and network access. Local agent runtimes only (Cursor, Claude Code, Codex CLI); ChatGPT chat without a local runtime cannot scan Drive.
metadata:
  author: Noah Dunn
  version: "1.0.0"
---

# GDIOCSpider

IR helper around the `gdiocspider` CLI. Same crawl pipeline as the classic tool; agents call smaller commands and read JSON.

## Prerequisites

- Package installed so `gdiocspider` is on PATH
- `credentials.json` / `token.json` (or a service account JSON) already on disk
- Absolute paths in `config.json`

Never print, quote, or commit secrets from `token.json` or `credentials.json`.

CLI details: [references/cli.md](references/cli.md). Config keys: [references/config.md](references/config.md). Example config: [assets/config.example.json](assets/config.example.json).

## Choose a path

**Pasted IOC string** (hash, IP, domain, email, path, UA, registry key) → `type`. Do not crawl Drive.

**Configure or run a Drive hunt** → draft `config.json`, then `list-files`, then `scan`.

## Type one indicator

```bash
gdiocspider type --value "INDICATOR"
```

Use `--no-strict` when the value is embedded in a sentence. Summarize `ioc_type` and `ioc_value` (may be defanged).

## Drive workflow

1. Copy [assets/config.example.json](assets/config.example.json) to a working `config.json`. Fill credential paths, ignore lists, MIME types, and keyword files from the user's request. Prefer relative-to-repo or user-given absolute paths — never copy hardcoded personal paths from a sample config in the tree.
2. Inventory first:

   ```bash
   gdiocspider list-files --config_file "/abs/path/config.json"
   ```

3. Confirm folders/files to skip or limit (`IGNORE_FILES_AND_FOLDERS`, `ONLY_SEARCH_FILES`) with the user when the inventory is large or sensitive.
4. Scan:

   ```bash
   gdiocspider scan --config_file "/abs/path/config.json" --output_file "/abs/path/indicator_data.json" --format json
   ```

   Classic CSV (also valid without the `scan` subcommand):

   ```bash
   gdiocspider --config_file "/abs/path/config.json" --output_file "/abs/path/indicator_data.csv"
   ```

5. After scan, summarize: top IOC types, files with the most hits, likely false positives (generic filenames, keywords). Do not dump every row unless asked.

If the stored token is missing or its refresh token is dead (`invalid_grant`), the CLI now falls back to the interactive OAuth flow automatically and prints the authorization URL — no manual `token.json` delete needed. Consent must be completed by the user in a browser on the same machine. Use `--no-browser` (or `GDIOCSPIDER_NO_BROWSER=1`) to only print the URL. Do not start an unattended OAuth browser flow inside the agent unless the user is present.

## Errors

JSON commands print `{"error": "..."}` on stdout and exit 1. Progress from crawls in JSON mode is on stderr — ignore it unless debugging.
