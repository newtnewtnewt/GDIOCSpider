# GDIOCSpider

**GDIOCSpider** is an open-source, configurable, Python Incident Response (IR) and Security Research tool specifically
catered around
IOC extraction and identification in GDrives with poor data context. Taken as an end-to-end application, this tool
crawls through a
provided GDrive, extracts IOCs from all files
processed, and outputs found results into a CSV file for research, analysis, and identification.

This tool comes complete with the standalone IOCFlagger package, which can be used in isolation to type IOCs purely
from their value, if a GDrive crawler is not your needed use-case but IOC enrichment and extraction is.

The tool supports a variety of file types, as well as ioc types. It's relatively simple, clean, efficient, and fast.

If you see something you'd like changed, please submit an Issue or better yet a Pull Request. I look forward to your
feedback.
This is an Open Source tool, so nothing I would love more than feedback or collaboration!

![Example of GDIOCSpider Running Gif](https://github.com/user-attachments/assets/4748600a-8ec3-4792-b676-fc99839db957)
![Example of The GDIOCSpider Running in Console](./markdown/ConsoleRun.png)
![GDIOCSpider Reduced Sample Output](./markdown/OutputExample.png)

# Setup

Unfortunately, everything using the GDrive API requires the creation of a GCP Application in addition to either OAuth
enablement or a
Service Account in GCP

1. Go to the Google Cloud Console.
2. Create a new project and enable the [Google Drive API](https://support.google.com/googleapi/answer/6158841?hl=en).
3. Either configure OAuth for
   a [personal account](https://console.cloud.google.com/apis/credentials/consent?pli=1&inv=1&invt=AbnkuQ&project=just-skyline-231218) (
   Recommended) and get credentials.json. Or Create a service
   account [using the steps here](https://developers.google.com/workspace/guides/create-credentials). You likely already
   have this if you are involved in the GCP ecosystem and get token.json.
4. Clone this repo
5. In the Root Directory, place your token.json file and credentials.json file (or potentially just your token.json if
   using a service account)
6. Examine `settings.py` for all settings. See if there's anything you want to change in `config.json`.
7. Install with your choice of tool, i.e: `pip install ./GDIOCSpider`
8. Run with required parameters: `gdiocspider --config_file="/tmp/config.json" --output_file="/tmp/indicator_data.csv"`
9. This will require authorization of your custom application on first run. A browser opens for OAuth consent and a `token.json` is written for reuse. If a stored `token.json` is later expired or revoked (`invalid_grant`), the tool re-runs the consent flow automatically — you no longer need to delete `token.json` by hand. Consent must be completed in a browser on the same machine (the redirect lands on `http://localhost`). Pass `--no-browser` (or set `GDIOCSPIDER_NO_BROWSER=1`) to only print the authorization URL instead of auto-opening a browser — handy for headless/SSH sessions or when auto-open picks the wrong browser profile.

The original two-flag command is unchanged. Subcommands are optional for agents and for targeted jobs:

```bash
gdiocspider --config_file="/tmp/config.json" --output_file="/tmp/indicator_data.csv"

gdiocspider scan --config_file="/tmp/config.json" --output_file="/tmp/indicator_data.csv"
gdiocspider scan --config_file="/tmp/config.json" --output_file="/tmp/indicator_data.json" --format json

gdiocspider list-files --config_file="/tmp/config.json"

gdiocspider type --value "1.1.1.1"
gdiocspider type --value "see 1.1.1.1 in this sentence" --no-strict
```

`--format json`: `scan` writes the structured results to `--output_file` and does not echo the array to stdout (only a short `Wrote N file record(s)...` pointer on stderr), so the terminal is not flooded — read or summarize the file instead. `type` prints its JSON to stdout; `list-files` prints a readable category/filename inventory to stdout (not a raw JSON blob). Progress logs go to stderr so they do not break JSON parsing.

# Use from any Agent Skills host

A portable Agent Skill lives at `.agents/skills/gdiocspider/` ([agentskills.io](https://agentskills.io/specification)). Cursor, Codex, and GitHub Copilot load that folder automatically. The skill tells the agent when to configure `config.json`, inventory Drive, scan, or type a pasted IOC.

Claude Code looks in `.claude/skills/` first, so a copy of the skill is committed there too (`.claude/skills/gdiocspider/`). It works on clone with no extra setup.

### Editing the skill (contributors)

`.agents/skills/gdiocspider/` is the **source of truth**; `.claude/skills/gdiocspider/` is a generated mirror. Edit the `.agents` copy only. A pre-commit hook keeps the mirror in sync automatically — enable it once per clone:

```bash
git config core.hooksPath .githooks
```

With the hook enabled, committing a change to the `.agents` skill regenerates and stages the `.claude` mirror. You can also sync manually with `sh scripts/sync-skills.sh`.

This skill needs a **local runtime** that can run `gdiocspider` and reach Google Drive with your existing `token.json`. Cursor, Claude Code, and Codex CLI can do that. ChatGPT chat without a local/CLI runtime cannot scan Drive or complete OAuth; use Codex/Cursor/Claude Code for crawls, or `gdiocspider type` only where a shell is available.

# Supported IOC Types

In the current version of IOCTyper, the following IOC Types are supported:

- IPv4
- IPv6
- SHA512
- SHA256
- SHA1
- MD5
- Email
- Registry Key
- User Agent
- Domain
- File Name
- File Path
- Keyword

# Supported File Types

The current version of the GDIOCSpider accommodates all the following file types:

- Text File
- CSV File
- PDF File
- JSON File
- Google Slides
- Google Docs
- Python Script
- Google Sheets

# Explanation of Settings

`settings.py` Is complete with an explanation of all the configuration settings and their default. The goal of this
tool is to offer the flexibility for you to accomplish your needs in the way you see fit.

`config.json` Is what you actually modify to change how the code will run, `settings.py` serves as documentation
