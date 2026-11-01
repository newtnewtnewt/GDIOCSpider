import os

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from gdiocspider.data_exporter import (
    export_all_indicator_data_to_csv,
    export_all_indicator_data_to_json,
)
from gdiocspider.file_scraper import extract_indicators_from_gdrive_file
from gdiocspider.settings import settings_store

# Scopes for Google Drive API
# https://developers.google.com/drive/api/quickstart/python
SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
]


_OPEN_BROWSER_OVERRIDE = None


def set_open_browser(open_browser):
    """Override whether the interactive OAuth flow opens a browser.

    ``False`` makes the flow only print the authorization URL (useful for a
    headless session, or when the OS default browser is the wrong Chrome
    profile). ``None`` restores the default, which honors the
    ``GDIOCSPIDER_NO_BROWSER`` environment variable.
    """
    global _OPEN_BROWSER_OVERRIDE
    _OPEN_BROWSER_OVERRIDE = open_browser


def _should_open_browser():
    """Resolve the browser preference: explicit override > env var > default."""
    if _OPEN_BROWSER_OVERRIDE is not None:
        return _OPEN_BROWSER_OVERRIDE
    flag = os.environ.get("GDIOCSPIDER_NO_BROWSER", "").strip().lower()
    return flag not in ("1", "true", "yes", "on")


def _run_interactive_oauth_flow():
    """Launch the interactive OAuth consent flow and return fresh credentials.

    Opens the consent page in a browser by default, and always prints the
    authorization URL to the console so it still works over a headless / SSH
    session, or when auto-open lands on the wrong browser profile. Set
    ``--no-browser`` / ``GDIOCSPIDER_NO_BROWSER=1`` to skip auto-open and only
    print the URL.
    """
    flow = InstalledAppFlow.from_client_secrets_file(
        settings_store.GCP_CREDENTIALS_FILE_PATH, SCOPES
    )
    open_browser = _should_open_browser()
    if open_browser:
        print(
            "Google Drive authorization required. A browser window will open; "
            "if it does not, copy the full URL printed below into a browser "
            "on THIS machine to continue."
        )
    else:
        print(
            "Google Drive authorization required (no-browser mode). Open the "
            "full URL printed below in a browser on THIS machine, then complete "
            "consent to continue."
        )
    return flow.run_local_server(port=0, open_browser=open_browser)


def _obtain_user_credentials(creds):
    """Return valid user credentials, re-authenticating interactively if needed.

    A stored token can carry a refresh token that Google has since revoked or
    expired. In that case ``creds.refresh()`` raises ``RefreshError``
    (``invalid_grant``). Instead of failing the whole run and asking the user to
    manually delete token.json, fall back to the interactive consent flow so the
    token is refreshed in a single step.
    """
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            return creds
        except RefreshError as e:
            print(
                f"Stored token could not be refreshed ({e}); "
                "starting interactive re-authentication."
            )
    return _run_interactive_oauth_flow()


def authenticate_google_drive(token_path):
    """
    Authenticate using a provided OAuth 2.0 token.

    Args:
        token_path (str): Path to the token.json file.

    Returns:
        service: Google Drive API service object.
    """
    try:
        creds = None

        # The file token.json stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if settings_store.USE_SERVICE_ACCOUNT:
            if os.path.exists(settings_store.GCP_TOKEN_FILE_PATH):
                creds = service_account.Credentials.from_service_account_file(
                    filename=settings_store.GCP_SERVICE_ACCOUNT_FILE, scopes=SCOPES
                )
                service = build("drive", "v3", credentials=creds)
                return service
            else:
                print(
                    f"Unable to locate service account credentials: {settings_store.GCP_TOKEN_FILE_PATH}. If you're trying to use a user account, please set USE_SERVICE_ACCOUNT to False in settings.py. Exiting."
                )
        else:
            if os.path.exists(settings_store.GCP_TOKEN_FILE_PATH):
                creds = Credentials.from_authorized_user_file(
                    settings_store.GCP_TOKEN_FILE_PATH, SCOPES
                )
            # If there are no (valid) credentials available, let the user log in.
            if not creds or not creds.valid:
                creds = _obtain_user_credentials(creds)
                # Save the credentials for the next run
                with open(settings_store.GCP_TOKEN_FILE_PATH, "w") as token:
                    token.write(creds.to_json())

            service = build("drive", "v3", credentials=creds)
            return service
    except Exception as e:
        print(f"Error during authentication: {e}")
        return None


def list_all_files(gdrive_service):
    """
    List all files in the user's Google Drive along with their full paths.

    Args:
        gdrive_service: Google Drive API service object.

    Returns:
        List of files (dict with 'id', 'name', and 'path').
    """

    def fetch_files_in_folder(parent_id, parent_path):
        """
        Recursively fetch files and folders within a parent folder.

        Args:
            parent_id (str): ID of the parent folder.
            parent_path (str): Path of the parent folder.

        Returns:
            List of files with their paths.
        """
        results = []
        page_token = None

        while True:
            response = (
                gdrive_service.files()
                .list(
                    q=f"'{parent_id}' in parents",
                    pageSize=1000,
                    fields="nextPageToken, files(id, name, mimeType, size)",
                    pageToken=page_token,
                )
                .execute()
            )

            for file in response.get("files", []):
                file_path = f"{parent_path}/{file['name']}"

                SEARCH_FILTER_FILE_MODE = False

                if settings_store.ONLY_SEARCH_FILES:
                    SEARCH_FILTER_FILE_MODE = True

                if (
                    file["mimeType"] == "application/vnd.google-apps.folder"
                    and file["name"] not in settings_store.IGNORE_FILES_AND_FOLDERS
                ):
                    # Recursively process folders
                    print(f"Searching folder {file_path} for more files...")
                    results.extend(fetch_files_in_folder(file["id"], file_path))
                else:
                    if file["name"] in settings_store.IGNORE_FILES_AND_FOLDERS:
                        print(
                            f"Ignoring folder {file['name']} due to file exclusion settings."
                        )
                        continue
                    elif file["mimeType"] not in settings_store.MIME_FILE_TYPES_TO_SCAN:
                        print(
                            f"Ignoring file {file['name']} due to file ending settings."
                        )
                        continue
                    elif SEARCH_FILTER_FILE_MODE:
                        if file["name"] not in settings_store.ONLY_SEARCH_FILES:
                            print(
                                f"Ignoring file {file['name']} due to SEARCH_FILTER_FILE_MODE being enabled."
                            )
                            continue
                    file["path"] = file_path
                    results.append(file)

            page_token = response.get("nextPageToken", None)
            if not page_token:
                break

        return results

    try:
        # Start recursion from the root folder
        root_files = fetch_files_in_folder("root", "")
        return root_files
    except HttpError as error:
        print(f"An error occurred: {error}")
        return []


def categorize_files(files):
    """
    Display files categorized by their types and return a dictionary with metadata.

    Args:
        files (list): List of files to display.

    Returns:
        dict: Dictionary of files categorized by their types with metadata.
    """
    MIME_TYPE_CATEGORIES = {
        "text/plain": "Text File",
        "text/csv": "CSV File",
        "application/pdf": "PDF File",
        "application/json": "JSON File",
        "application/vnd.google-apps.presentation": "Google Slides",
        "application/vnd.google-apps.document": "Google Docs",
        "text/x-python": "Python Script",
        "application/vnd.google-apps.spreadsheet": "Google Sheets",
        "Unknown": "Unknown Type",
    }

    categorized_files = {}

    print(f"\nAvailable Files by Category ({len(files)} total):")

    for file in files:
        mime_type = file.get("mimeType", "Unknown")
        category = MIME_TYPE_CATEGORIES.get(mime_type, "Other")
        file_path = file.get("path", "Unknown Path")
        file_metadata = {
            "id": file.get("id"),
            "name": file.get("name"),
            "path": file_path,
            "mimeType": mime_type,
            "category": category,
            "size": file.get("size", "Unknown"),
        }

        if category not in categorized_files:
            categorized_files[category] = []
        categorized_files[category].append(file_metadata)

    for category, files_list in categorized_files.items():
        print(f"\n{category} ({len(files_list)}):")
        for file_meta in files_list:
            print(file_meta["path"])
    print()
    return categorized_files


def get_gdrive_service_object():
    """
    Use the token.json file to authenticate with Google Drive, if not present
    this will pull open a new browser window to authenticate, as long as you've correctly
    configured the GCloud Application using the setup

    Returns:
        GDrive object to perform actions

    """
    GCP_TOKEN_FILE_PATH = settings_store.GCP_TOKEN_FILE_PATH

    service = authenticate_google_drive(GCP_TOKEN_FILE_PATH)
    if not service:
        print(
            f"Was unable to authenticate with Google Drive at path {GCP_TOKEN_FILE_PATH}, if an old token.json is present, delete and re-run"
        )
        return None
    return service


def gather_valid_gdrive_files(gdrive_service):
    """
    This grabs all the valid files according to the settings and then categorizes them.

    Args:
        gdrive_service: A service object for interacting with Google Drive.

    Returns:
        The dictionary of all files with their associated metadata

    """
    files = list_all_files(gdrive_service)

    if not files:
        print("No files found.")
        return {}

    organized_file_collection = categorize_files(files)

    return organized_file_collection


def process_gdrive_files(gdrive_service, organized_file_collection):
    """
    Perform IOC extraction on all identified files

    Args:
        gdrive_service: A service object for interacting with Google Drive.
        organized_file_collection: A dictionary of all files with their associated metadata.

    Returns:
        Indicators with associated file type and metadata

    """
    all_processed_data = []
    for file_type, files_metadata in organized_file_collection.items():
        for file_metadata in files_metadata:
            all_indicators = extract_indicators_from_gdrive_file(
                gdrive_service, file_type, file_metadata
            )
            all_processed_data.append(
                {
                    "file_type": file_type,
                    "file_metadata": file_metadata,
                    "all_indicators": all_indicators,
                }
            )
    return all_processed_data


def execute_list_files():
    """
    Authenticate and return the files that would be scanned, without extracting IOCs.
    """
    gdrive_service = get_gdrive_service_object()
    if not gdrive_service:
        return None
    return gather_valid_gdrive_files(gdrive_service)


def execute_gdrive_crawler(output_format="csv"):
    """
    The function that handles everything
    """
    gdrive_service = get_gdrive_service_object()
    if not gdrive_service:
        return None

    organized_file_collection = gather_valid_gdrive_files(gdrive_service)
    finalized_processed_data = process_gdrive_files(
        gdrive_service, organized_file_collection
    )
    if output_format == "json":
        export_all_indicator_data_to_json(finalized_processed_data)
    else:
        export_all_indicator_data_to_csv(finalized_processed_data)
    return finalized_processed_data


def main(argv=None):
    from gdiocspider.cli import main as cli_main

    cli_main(argv)


if __name__ == "__main__":
    main()
