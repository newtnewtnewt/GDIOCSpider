"""
SEARCH_EXCLUSION_LIST: A list of all types to disable the IOC flagger from checking for. The only recommended
default is Keyword, due to performance and high likelihood of false positives.

SEARCH_EXCLUSION_LIST = [
    "IPv4",
    "IPv6",
    "SHA512",
    "SHA256",
    "SHA1",
    "MD5",
    "Email",
    "Registry Key",
    "User Agent",
    "Domain Name",
    "File Name",
    "File Path",
    "Keyword",
]

IOC_TYPER_STRICT_MODE: Defaulted to False. If True, this uses regex fullmatch, otherwise it uses regex search.

PERMITTED_DELIMITERS_TO_CHECK_AGAINST: Each of the delimiters list will be used to split the file into a list of strings in order to
be analyzed for IOC presence. This is iterative, so it will convert all the delimiters into a temporary string
in the body of text and then split the entirety of the text on all the delimiters

MIME_FILE_TYPES_TO_SCAN: A list of strings of all file types to scan for IOC presence. Full available list can be found here:
https://mimetype.io/all-types

IGNORE_FILES_AND_FOLDERS: A list of strings of all files and folders to avoid scanning. This is particularly useful if you
have a folder loaded with large files that you don't want to scan. (Or if using sensitive data)

ONLY_SEARCH_FILES: A list of strings of filenames. This takes priority from, but works in tandem with IGNORE_FILES_AND_FOLDERS.
This will only search for IOC presence in the files listed in ONLY_SEARCH_FILES,
ignoring the folders listed in IGNORE_FILES_AND_FOLDERS.

KEYWORD_FILES_TO_USE: A list of strings of filenames. All text files listed here will be added to a dictionary of keywords
to check for if present in the files scanned for. These files need to be placed in the folder at ioc_flagger/src/data_bank

DEFANG_BEFORE_EXPORT: Defangs all indicators before sending them back to the user if set to True. This is specifically important
for domains and file names

ROOT_DIR: Should not need modified unless you are running the script from a different location
GCP_TOKEN_FILE_PATH: Should not need modified as long as token.json is in the root folder
GCP_CREDENTIALS_FILE_PATH: Should not need modified as long as credentials.json is in the root folder

USE_SERVICE_ACCOUNT: False by default, if you need to use a provisioned service account, set this to True
GCP_SERVICE_ACCOUNT_FILE: Should not need modified as long as token.json is in the root folder. This is the path to the service account token.json file.
Will not be used if USE_SERVICE_ACCOUNT is False.

"""

import os

SEARCH_EXCLUSION_LIST = os.getenv("SEARCH_EXCLUSION_LIST", [""])
IOC_TYPER_STRICT_MODE = os.getenv("IOC_TYPER_STRICT_MODE", False)
PERMITTED_DELIMITERS_TO_CHECK_AGAINST = os.getenv(
    "PERMITTED_DELIMITERS_TO_CHECK_AGAINST", [",", "\n", "\r", ":", "|", " "]
)

MIME_FILE_TYPES_TO_SCAN = os.getenv(
    "MIME_FILE_TYPES_TO_SCAN",
    [
        "text/plain",
        "text/csv",
        "application/pdf",
        "application/json",
        "application/vnd.google-apps.presentation",
        "application/vnd.google-apps.document",
        "text/x-python",
        "application/vnd.google-apps.spreadsheet",
    ],
)

IGNORE_FILES_AND_FOLDERS = os.getenv(
    "IGNORE_FILES_AND_FOLDERS",
    [
        "Misc",
        "Reference Letters",
        "School",
        "Work Stuff",
    ],
)

ONLY_SEARCH_FILES = os.getenv("ONLY_SEARCH_FILES", [])

KEYWORD_FILES_TO_USE = os.getenv("KEYWORD_FILES_TO_USE", ["keywords.txt"])

DEFANG_BEFORE_EXPORT = os.getenv("DEFANG_BEFORE_EXPORT", True)

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
GCP_TOKEN_FILE_PATH = os.getenv(
    "GCP_TOKEN_FILE_PATH", os.path.join(ROOT_DIR, "token.json")
)
GCP_CREDENTIALS_FILE_PATH = os.getenv(
    "GCP_CREDENTIALS_FILE_PATH", os.path.join(ROOT_DIR, "credentials.json")
)
USE_SERVICE_ACCOUNT = os.getenv("USE_SERVICE_ACCOUNT", False)
GCP_SERVICE_ACCOUNT_FILE = os.getenv(
    "GCP_SERVICE_ACCOUNT_FILE", os.path.join(ROOT_DIR, "token.json")
)
