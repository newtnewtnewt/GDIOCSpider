# GDIOCSpider CLI

Install from the repo root (`pip install .`). The console script is `gdiocspider`.

Progress messages stay on stderr when `--format json`. Structured results go to stdout. Failures use exit code 1 and, in JSON mode, print `{"error": "..."}` on stdout.

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

`--format json` writes the nested record array to the output file and prints that same array on stdout.

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

Auth needs an existing token when possible. First-run OAuth opens a browser; do not try to complete that interactively inside the agent unless the user is present.

## list-files

Auth + inventory only. No downloads, no IOC extraction.

```bash
gdiocspider list-files --config_file "/abs/path/config.json"
```

Stdout:

```json
{
  "files": {
    "Text File": [{"id": "...", "name": "...", "path": "...", "mimeType": "...", "category": "Text File", "size": "..."}]
  },
  "total": 1
}
```

Use this before a full crawl to propose `IGNORE_FILES_AND_FOLDERS` or `ONLY_SEARCH_FILES`.

## type

Classify one string with IOCFlagger. Does not touch Drive. No config file required.

```bash
gdiocspider type --value "1.1.1.1"
gdiocspider type --value "see 1.1.1.1 in this sentence" --no-strict
```

Stdout: `{"ioc_value": "...", "ioc_type": "..."}`.

`--strict` (default) uses regex fullmatch after refang. `--no-strict` searches inside the string. Defanging follows the process-wide `DEFANG_BEFORE_EXPORT` default (true unless a config was loaded earlier in the same process).
