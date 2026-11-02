# GDIOCSpider CLI

Install from the repo root (`pip install .`). The console script is `gdiocspider`.

Progress messages stay on stderr when `--format json`. `type` prints its JSON result to stdout; `list-files` prints a readable category/filename inventory to stdout (not a raw JSON blob); `scan` writes its JSON to `--output_file` and does **not** echo the array to stdout (only a one-line `Wrote N file record(s)...` pointer on stderr), so the terminal is never flooded. Failures use exit code 1 and, in JSON mode, print `{"error": "..."}` on stdout.

Do not print or commit `token.json` or `credentials.json`.

## Classic scan (CSV)

Same as the original tool. Omitting a subcommand requires both flags and always writes CSV:

```bash
gdiocspider --config_file "/abs/path/config.json" --output_file "/abs/path/indicator_data.csv"
```

## scan

Crawl Drive, extract IOCs, write `--output_file`.

```bash
gdiocspider scan --config_file "/abs/path/config.json" --output_file "/abs/path/indicator_data.csv"
gdiocspider scan --config_file "/abs/path/config.json" --output_file "/abs/path/indicator_data.json" --format json
```

`--format json` writes the nested record array to `--output_file`. It is **not** echoed to stdout (that would flood the terminal) — read or summarize the file to inspect results.

Each record:

```json
{
  "file_type": "Text File",
  "file_metadata": {
    "id": "...",
    "name": "notes.txt",
    "path": "/folder/notes.txt",
    "mimeType": "text/plain",
    "category": "Text File",
    "size": "123"
  },
  "all_indicators": [
    {"value": "1[.]2[.]3[.]4", "type": "IPv4", "count": 2}
  ]
}
```

CSV columns: Indicator Value, Indicator Type, Count, File Name, File Path, File Type, File ID, File Size.

Auth needs an existing token when possible. First-run OAuth opens a browser; do not try to complete that interactively inside the agent unless the user is present. See [Authentication](#authentication).

## list-files

Auth + inventory only. No downloads, no IOC extraction.

```bash
gdiocspider list-files --config_file "/abs/path/config.json"
```

Stdout is a readable inventory (not a JSON blob) — each category, the file names under it, and a total:

```
CSV File (2)
  - indicator_data.csv
  - DELETE_ME.csv
Text File (1)
  - DELETE_ME.txt

Total: 8 file(s)
```

Progress/auth messages go to stderr. Use this before a full crawl to propose `IGNORE_FILES_AND_FOLDERS` or `ONLY_SEARCH_FILES`.

## Authentication

`scan` and `list-files` authenticate with Google Drive before doing anything else, using `GCP_TOKEN_FILE_PATH` / `GCP_CREDENTIALS_FILE_PATH` from the config.

- A valid `token.json` is used directly.
- An expired token with a working refresh token is refreshed silently.
- If the token is missing, or its refresh token is revoked/expired (`invalid_grant`), the tool falls back to the interactive OAuth consent flow automatically — no need to manually delete `token.json` first. The authorization URL is always printed to the console, and a browser is opened by default.

Consent must be completed in a browser **on the same machine** (the redirect lands on `http://localhost:<port>`). The Google *account* you pick on the consent screen is what matters, not which browser profile the tab opens in — use "Use another account" if the wrong one auto-opens.

Skip the browser auto-open (print the URL only) with either:

```bash
gdiocspider list-files --no-browser --config_file "/abs/path/config.json"
GDIOCSPIDER_NO_BROWSER=1 gdiocspider scan --config_file "/abs/path/config.json" --output_file "/abs/path/out.json" --format json
```

The `--no-browser` flag overrides the env var. Useful for headless/SSH sessions, or when auto-open lands on the wrong browser. Do not complete OAuth unattended inside an agent unless the user is present.

## type

Classify one string with IOCFlagger. Does not touch Drive. No config file required.

```bash
gdiocspider type --value "1.1.1.1"
gdiocspider type --value "see 1.1.1.1 in this sentence" --no-strict
```

Stdout: `{"ioc_value": "...", "ioc_type": "..."}`.

`--strict` (default) uses regex fullmatch after refang. `--no-strict` searches inside the string. Defanging follows the process-wide `DEFANG_BEFORE_EXPORT` default (true unless a config was loaded earlier in the same process).
