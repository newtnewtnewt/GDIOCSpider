# GDIOCSpider — CLI Demo Transcript (captured dry run)

Real output captured from a live Google Drive crawl on 2026-11-01. Repetitive per-indicator lines are trimmed (`... (N more IOC lines) ...`); every per-file total and summary is intact. Use this as a fallback if Drive/Wi-Fi is unavailable on stage. Commands run from the repo root.

## 1a. File inventory (`list-files`)

> Before crawling, see exactly what GDIOCSpider would touch.

```console
$ gdiocspider list-files --config_file demo/configs/01_full_scan.json
{
  "files": {
    "Google Sheets": [
      {
        "id": "1F9YwgNuwmTA1KfF3Od27RZPON12txw2V4j_VOs5W2xI",
        "name": "indicator_data",
        "path": "/indicator_data",
        "mimeType": "application/vnd.google-apps.spreadsheet",
        "category": "Google Sheets",
        "size": "2091"
      },
      {
        "id": "1GHAKVmPRLu1BSA1Y-R9HtESHmt-ATJNzZXKPT7wvD60",
        "name": "DELETE_ME",
        "path": "/DELETE_ME",
        "mimeType": "application/vnd.google-apps.spreadsheet",
        "category": "Google Sheets",
        "size": "1024"
      }
    ],
    "CSV File": [
      {
        "id": "1dpaacj7Y1r3L1S-uYsx51pY8VXidkL3M",
        "name": "indicator_data.csv",
        "path": "/indicator_data.csv",
        "mimeType": "text/csv",
        "category": "CSV File",
        "size": "8869"
      },
      {
        "id": "13FMfzsRj_ob2CuMnxSLrUvKQIf28AJsi",
        "name": "DELETE_ME.csv",
        "path": "/DELETE_ME.csv",
        "mimeType": "text/csv",
        "category": "CSV File",
        "size": "1080"
      }
    ],
    "Google Docs": [
      {
        "id": "1OxNZ21Jh4_9rahHpG3Gm0-nryfx3GB5qnwxo8wsW8pI",
        "name": "DELETE_ME_GDOCS",
        "path": "/DELETE_ME_GDOCS",
        "mimeType": "application/vnd.google-apps.document",
        "category": "Google Docs",
        "size": "3077"
      }
    ],
    "JSON File": [
      {
        "id": "1z2dY6uKMQyYxwkoEHAt6oigXBCnxslQu",
        "name": "DELETE_ME.json",
        "path": "/DELETE_ME.json",
        "mimeType": "application/json",
        "category": "JSON File",
        "size": "2095"
      }
    ],
    "Text File": [
      {
        "id": "1rwSyKt1tIiNGNO7Rnv7TdpWOw35NGuUD",
        "name": "DELETE_ME.txt",
        "path": "/DELETE_ME.txt",
        "mimeType": "text/plain",
        "category": "Text File",
        "size": "1299"
      }
    ],
    "Python Script": [
      {
        "id": "13NGBtyGjTYgsxKPSn1oU19aEk6OpRxbX",
        "name": "DELETE_ME.py",
        "path": "/DELETE_ME.py",
        "mimeType": "text/x-python",
        "category": "Python Script",
        "size": "20"
      }
    ]
  },
  "total": 8
}
```

**8 files**, grouped by category. No downloads, no extraction.

## 1b. IOC inventory (classic CSV scan)

> Crawl everything and extract indicators to CSV.

```console
$ gdiocspider --config_file demo/configs/01_full_scan.json --output_file demo/output/full.csv
Beginning GDIOCSpider with demo/configs/01_full_scan.json, demo/output/full.csv


Ignoring folder old_school_stuff due to file exclusion settings.

Available Files by Category (8 total):

Google Sheets (2):
/indicator_data
/DELETE_ME

CSV File (2):
/indicator_data.csv
/DELETE_ME.csv

Google Docs (1):
/DELETE_ME_GDOCS

JSON File (1):
/DELETE_ME.json

Text File (1):
/DELETE_ME.txt

Python Script (1):
/DELETE_ME.py

Downloaded indicator_data.xlsx to ...data_dumpster\indicator_data.xlsx
IOC Found in XLSX: Type: IPv4, Value: 203[.]0[.]113[.]42
IOC Found in XLSX: Type: File Path, Value: /DELETE_ME_GDOCS
IOC Found in XLSX: Type: IPv4, Value: 10[.]0[.]0[.]15
    ... (211 more IOC lines) ...
Total IOC Count: 214, IPv4: 31, File Path: 17, Email: 14, File Name: 124, Domain Name: 18, MD5: 6, SHA256: 4
Deleted downloaded file: ...data_dumpster\indicator_data.xlsx

Downloaded DELETE_ME.xlsx to ...data_dumpster\DELETE_ME.xlsx
IOC Found in XLSX: Type: IPv4, Value: 192[.]168[.]1[.]1
IOC Found in XLSX: Type: Domain Name, Value: fake[.]sh
IOC Found in XLSX: Type: File Name, Value: fake[.]py
    ... (3 more IOC lines) ...
Total IOC Count: 6, IPv4: 1, Domain Name: 4, File Name: 1
Deleted downloaded file: ...data_dumpster\DELETE_ME.xlsx

Downloaded indicator_data.csv to ...data_dumpster\indicator_data.csv
IOC Found in CSV: Type: IPv4, Value: 203[.]0[.]113[.]42
IOC Found in CSV: Type: File Path, Value: /DELETE_ME_GDOCS
IOC Found in CSV: Type: IPv4, Value: 10[.]0[.]0[.]15
    ... (211 more IOC lines) ...
Total IOC Count: 214, IPv4: 31, File Path: 17, Email: 14, File Name: 124, Domain Name: 18, MD5: 6, SHA256: 4
Deleted downloaded file: ...data_dumpster\indicator_data.csv

Downloaded DELETE_ME.csv to ...data_dumpster\DELETE_ME.csv
IOC Found in CSV: Type: IPv4, Value: 192[.]168[.]1[.]100
IOC Found in CSV: Type: IPv4, Value: 10[.]0[.]0[.]15
IOC Found in CSV: Type: Domain Name, Value: www[.]benign-site[.]com
    ... (29 more IOC lines) ...
Total IOC Count: 32, IPv4: 14, Domain Name: 7, Email: 6, MD5: 3, SHA256: 2
Deleted downloaded file: ...data_dumpster\DELETE_ME.csv

Downloaded DELETE_ME_GDOCS.pdf to ...data_dumpster\DELETE_ME_GDOCS.pdf
IOC Found in Text: Type: IPv4, Value: 203[.]0[.]113[.]42
IOC Found in Text: Type: IPv4, Value: 10[.]0[.]0[.]15
IOC Found in Text: Type: Email, Value: jane[.]doe@company[.]com
    ... (14 more IOC lines) ...
Total IOC Count: 17, IPv4: 5, Email: 3, Domain Name: 7, File Name: 1, SHA256: 1
Deleted downloaded file: ...data_dumpster\DELETE_ME_GDOCS.pdf

Downloaded DELETE_ME.json to ...data_dumpster\DELETE_ME.json
IOC Found in JSON Dict Value: Type: Domain Name, Value: benign-site[.]com
IOC Found in JSON Dict Value: Type: IPv4, Value: 192[.]168[.]0[.]1
IOC Found in JSON Dict Value: Type: Domain Name, Value: bad-actor[.]com
    ... (18 more IOC lines) ...
Total IOC Count: 21, Domain Name: 4, IPv4: 6, MD5: 3, SHA256: 2, Email: 4, File Name: 2
Deleted downloaded file: ...data_dumpster\DELETE_ME.json

Downloaded DELETE_ME.txt to ...data_dumpster\DELETE_ME.txt
IOC Found in Text: Type: IPv4, Value: 192[.]168[.]1[.]100
IOC Found in Text: Type: Domain Name, Value: www[.]malicious-site[.]com
IOC Found in Text: Type: Email, Value: phishing@badguys[.]com
    ... (9 more IOC lines) ...
Total IOC Count: 12, IPv4: 5, Domain Name: 3, Email: 1, MD5: 2, SHA256: 1
Deleted downloaded file: ...data_dumpster\DELETE_ME.txt

Downloaded DELETE_ME.py to ...data_dumpster\DELETE_ME.py
IOC Found in Text: Type: IPv4, Value: 192[.]168[.]0[.]2
Total IOC Count: 1, IPv4: 1
Deleted downloaded file: ...data_dumpster\DELETE_ME.py

DONE! Finished exporting all indicator data to demo/output/full.csv
```

**182 unique indicators across 8 files** — IPv4 62, Domain 46, Email 28, File Name 18, MD5 14, SHA256 10, File Path 4. Values defanged on export.

## 1c. Targeting — `ONLY_SEARCH_FILES`

> Same Drive, scoped to just DELETE_ME.json and DELETE_ME.txt.

```console
$ gdiocspider scan --config_file demo/configs/02_targeted.json --output_file demo/output/targeted.json --format json
Beginning GDIOCSpider with demo/configs/02_targeted.json, demo/output/targeted.json


Ignoring file indicator_data due to SEARCH_FILTER_FILE_MODE being enabled.
Ignoring file indicator_data.csv due to SEARCH_FILTER_FILE_MODE being enabled.
Ignoring file DELETE_ME_GDOCS due to SEARCH_FILTER_FILE_MODE being enabled.
Ignoring file DELETE_ME due to SEARCH_FILTER_FILE_MODE being enabled.
Ignoring file DELETE_ME.csv due to SEARCH_FILTER_FILE_MODE being enabled.
Ignoring file DELETE_ME.py due to SEARCH_FILTER_FILE_MODE being enabled.
Ignoring folder old_school_stuff due to file exclusion settings.

Available Files by Category (2 total):

JSON File (1):
/DELETE_ME.json

Text File (1):
/DELETE_ME.txt

Downloaded DELETE_ME.json to ...data_dumpster\DELETE_ME.json
IOC Found in JSON Dict Value: Type: Domain Name, Value: benign-site[.]com
IOC Found in JSON Dict Value: Type: IPv4, Value: 192[.]168[.]0[.]1
IOC Found in JSON Dict Value: Type: Domain Name, Value: bad-actor[.]com
    ... (18 more IOC lines) ...
Total IOC Count: 21, Domain Name: 4, IPv4: 6, MD5: 3, SHA256: 2, Email: 4, File Name: 2
Deleted downloaded file: ...data_dumpster\DELETE_ME.json

Downloaded DELETE_ME.txt to ...data_dumpster\DELETE_ME.txt
IOC Found in Text: Type: IPv4, Value: 192[.]168[.]1[.]100
IOC Found in Text: Type: Domain Name, Value: www[.]malicious-site[.]com
IOC Found in Text: Type: Email, Value: phishing@badguys[.]com
    ... (9 more IOC lines) ...
Total IOC Count: 12, IPv4: 5, Domain Name: 3, Email: 1, MD5: 2, SHA256: 1
Deleted downloaded file: ...data_dumpster\DELETE_ME.txt

DONE! Finished exporting all indicator data to demo/output/targeted.json
```

Only **2 files, 33 indicators**. (Progress on stderr; JSON results on stdout / `--output_file`.)

## 1c. Noise reduction — `SEARCH_EXCLUSION_LIST`

> Drop the false-positive-heavy File Name and File Path types.

```console
$ gdiocspider scan --config_file demo/configs/03_exclude_types.json --output_file demo/output/network_only.json --format json
IOC Found in Text: Type: Domain Name, Value: www[.]malicious-site[.]com
IOC Found in Text: Type: Email, Value: phishing@badguys[.]com
    ... (9 more IOC lines) ...
Total IOC Count: 12, IPv4: 5, Domain Name: 3, Email: 1, MD5: 2, SHA256: 1
Deleted downloaded file: ...data_dumpster\DELETE_ME.txt

Downloaded DELETE_ME.py to ...data_dumpster\DELETE_ME.py
IOC Found in Text: Type: IPv4, Value: 192[.]168[.]0[.]2
Total IOC Count: 1, IPv4: 1
Deleted downloaded file: ...data_dumpster\DELETE_ME.py

DONE! Finished exporting all indicator data to demo/output/network_only.json
```

**160 indicators** — the 22 File Name/Path rows are gone, leaving network/host IOCs.

## 1d. Keyword search — `KEYWORD_FILEPATHS_TO_USE`

> Hunt arbitrary terms from demo/keywords.txt, not just structured IOCs.

```console
$ gdiocspider scan --config_file demo/configs/04_keywords.json --output_file demo/output/keywords.json --format json
Beginning GDIOCSpider ... (progress trimmed) ...

Keyword hits (Type: Keyword):
    9  email
    8  hash
    6  domain
    4  traffic
    3  detected
    3  ipsum
    2  Malware
    2  Lorem
    1  Garbage
    1  weird
    1  gibberish
```

**208 total indicators, 26 of them Keyword.** Edit demo/keywords.txt live to add a term.

## Bonus. IOCFlagger `type` (no Drive) — strict vs. loose

> Classify a single string instantly; no Drive, no config.

```console
$ gdiocspider type --value "8.8.8.8:443"      # strict
## 8.8.8.8:443
{
  "ioc_value": "8[.]8[.]8[.]8:443",
  "ioc_type": "Unknown"
}
## d41d8cd98f00b204e9800998ecf8427e
{
  "ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
  "ioc_type": "MD5"
}
## evil-domain.ru
{
  "ioc_value": "evil-domain[.]ru",
  "ioc_type": "Domain Name"
}

$ gdiocspider type --value "8.8.8.8:443" --no-strict   # loose
{
  "ioc_value": "8[.]8[.]8[.]8",
  "ioc_type": "IPv4"
}
```

Strict rejects the trailing `:443` (Unknown); loose extracts the IPv4.
