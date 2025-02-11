import json


class Settings:
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

    KEYWORD_FILEPATHS_TO_USE: A list of strings of FILEPATHS. All text files listed here will be added to a dictionary of keywords
    to check for if present in the files scanned for.

    DEFANG_BEFORE_EXPORT: Defangs all indicators before sending them back to the user if set to True. This is specifically important
    for domains and file names

    GCP_TOKEN_FILE_PATH: Should not need modified as long as absolute path is provided for token.json
    GCP_CREDENTIALS_FILE_PATH: Should not need modified as long as absolute path is provided for credentials.json

    USE_SERVICE_ACCOUNT: False by default, if you need to use a provisioned service account, set this to True
    GCP_SERVICE_ACCOUNT_FILE_PATH: Should not need modified as long as token.json is in the root folder. This is the path to the service account token.json file.
    Will not be used if USE_SERVICE_ACCOUNT is False.

    """

    def __init__(self, config_file_path):
        self.config_file_path = config_file_path
        self.output_file_path = "indicator_data.csv"
        self.SEARCH_EXCLUSION_LIST = [
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
        self.IOC_TYPER_STRICT_MODE = False
        self.PERMITTED_DELIMITERS_TO_CHECK_AGAINST = [",", "\n", "\r", ":", "|", " "]
        self.MIME_FILE_TYPES_TO_SCAN = [
            "text/plain",
            "text/csv",
            "application/pdf",
            "application/json",
            "application/vnd.google-apps.presentation",
            "application/vnd.google-apps.document",
            "text/x-python",
            "application/vnd.google-apps.spreadsheet",
        ]
        self.IGNORE_FILES_AND_FOLDERS = [
            "Misc",
            "Reference Letters",
            "School",
            "Work Stuff",
        ]
        self.ONLY_SEARCH_FILES = []
        self.KEYWORD_FILEPATHS_TO_USE = ["/root/keywords.txt"]
        self.DEFANG_BEFORE_EXPORT = True
        self.GCP_TOKEN_FILE_PATH = "token.json"
        self.GCP_CREDENTIALS_FILE_PATH = "credentials.json"
        self.USE_SERVICE_ACCOUNT = False
        self.GCP_SERVICE_ACCOUNT_FILE = "token.json"

    def update_file_path(self, new_file_path):
        self.config_file_path = new_file_path

    def update_output_file_path(self, new_output_file_path):
        self.output_file_path = new_output_file_path

    def initialize_settings(self):
        try:
            # Load configuration from config.json
            with open(self.config_file_path, "r") as config_file:
                config = json.load(config_file)
        except FileNotFoundError:
            print(
                f"Couldn't find config file at the specified path {self.config_file_path}, exiting."
            )
            exit(1)

        self.SEARCH_EXCLUSION_LIST = config.get("SEARCH_EXCLUSION_LIST", [""])
        self.IOC_TYPER_STRICT_MODE = config.get("IOC_TYPER_STRICT_MODE", False)
        self.PERMITTED_DELIMITERS_TO_CHECK_AGAINST = config.get(
            "PERMITTED_DELIMITERS_TO_CHECK_AGAINST", [",", "\n", "\r", ":", "|", " "]
        )

        self.MIME_FILE_TYPES_TO_SCAN = config.get(
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

        self.IGNORE_FILES_AND_FOLDERS = config.get(
            "IGNORE_FILES_AND_FOLDERS",
            [
                "Misc",
                "Reference Letters",
                "School",
                "Work Stuff",
            ],
        )

        self.ONLY_SEARCH_FILES = config.get("ONLY_SEARCH_FILES", [])

        self.KEYWORD_FILEPATHS_TO_USE = config.get("KEYWORD_FILEPATHS_TO_USE", [])

        self.DEFANG_BEFORE_EXPORT = config.get("DEFANG_BEFORE_EXPORT", True)

        self.GCP_TOKEN_FILE_PATH = config.get("GCP_TOKEN_FILE_PATH", "token.json")
        self.GCP_CREDENTIALS_FILE_PATH = config.get(
            "GCP_CREDENTIALS_FILE_PATH", "credentials.json"
        )
        self.USE_SERVICE_ACCOUNT = config.get("USE_SERVICE_ACCOUNT", False)
        self.GCP_SERVICE_ACCOUNT_FILE = config.get(
            "GCP_SERVICE_ACCOUNT_FILE_PATH", "token.json"
        )


# This is a singleton we'll actually initialize at launch
settings_store = Settings("config.json")
