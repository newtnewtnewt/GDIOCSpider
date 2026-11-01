# config.json settings

Copy [assets/config.example.json](../assets/config.example.json) and use **absolute paths** for files on disk. Do not reuse personal/Pycharm paths from a sample `config.json` in the repo.

Field meanings (also documented in `gdiocspider/settings.py`):

| Key | Role |
| --- | --- |
| `SEARCH_EXCLUSION_LIST` | IOC types to skip. Names: `IPv4`, `IPv6`, `SHA512`, `SHA256`, `SHA1`, `MD5`, `Email`, `Registry Key`, `User Agent`, `Domain Name`, `File Name`, `File Path`, `Keyword`. Empty list = check all. Keyword is noisy; exclude it unless the user supplied keyword files. |
| `IOC_TYPER_STRICT_MODE` | Drive-scan typing uses search vs fullmatch internally via IOCFlagger; keep `false` unless the user wants stricter matching. |
| `PERMITTED_DELIMITERS_TO_CHECK_AGAINST` | Characters used to split file text before IOC search. |
| `MIME_FILE_TYPES_TO_SCAN` | Drive MIME types to download and parse. |
| `IGNORE_FILES_AND_FOLDERS` | Exact file or folder **names** (not full paths) to skip. |
| `ONLY_SEARCH_FILES` | If non-empty, only these file names are scanned (still honors ignore list). |
| `KEYWORD_FILEPATHS_TO_USE` | Absolute paths to newline-delimited keyword lists. |
| `DEFANG_BEFORE_EXPORT` | Replace `.` with `[.]` on export. |
| `GCP_TOKEN_FILE_PATH` | OAuth token JSON. |
| `GCP_CREDENTIALS_FILE_PATH` | OAuth client secrets JSON. |
| `USE_SERVICE_ACCOUNT` | `true` to use a service account instead of user OAuth. |
| `GCP_SERVICE_ACCOUNT_FILE_PATH` | Service account JSON path (used when `USE_SERVICE_ACCOUNT` is true). |

Supported scan MIME types by default: `text/plain`, `text/csv`, `application/pdf`, `application/json`, `application/vnd.google-apps.presentation`, `application/vnd.google-apps.document`, `text/x-python`, `application/vnd.google-apps.spreadsheet`.
