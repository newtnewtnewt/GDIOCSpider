import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from file_scraper.file_scraper import process_gdrive_file

# Scopes for Google Drive API
# https://developers.google.com/drive/api/quickstart/python
SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
]


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
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    "credentials.json", SCOPES
                )
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open("token.json", "w") as token:
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
                # TODO: Pull this in from a settings file
                # https://mimetype.io/all-types
                MIME_FILE_TYPES_TO_SCAN = [
                    "text/plain",
                    "text/csv",
                    "application/pdf",
                    "application/json",
                    "application/vnd.google-apps.presentation",
                    "application/vnd.google-apps.document",
                    "text/x-python",
                    "application/vnd.google-apps.spreadsheet",
                ]
                # IGNORE_FILES_AND_FOLDERS = ["old_school_stuff"]
                IGNORE_FILES_AND_FOLDERS = [
                    "Misc",
                    "Reference Letters",
                    "School",
                    "Work Stuff",
                ]

                if (
                    file["mimeType"] == "application/vnd.google-apps.folder"
                    and file["name"] not in IGNORE_FILES_AND_FOLDERS
                ):
                    # Recursively process folders
                    print(f"Searching folder {file_path} for more files...")
                    results.extend(fetch_files_in_folder(file["id"], file_path))
                else:
                    if file["name"] in IGNORE_FILES_AND_FOLDERS:
                        print(
                            f"Ignoring folder {file['name']} due to file exclusion settings."
                        )
                        continue
                    if file["mimeType"] not in MIME_FILE_TYPES_TO_SCAN:
                        print(
                            f"Ignoring file {file['name']} due to file ending settings."
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
            "size": file.get("size", "Unknown"),
        }

        if category not in categorized_files:
            categorized_files[category] = []
        categorized_files[category].append(file_metadata)

    for category, files_list in categorized_files.items():
        print(f"\n{category} ({len(files_list)}):")
        for file_meta in files_list:
            print(file_meta["path"])

    return categorized_files


def get_gdrive_service_object():
    ROOT_DIR = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    GCP_TOKEN_FILE_PATH = os.getenv(
        "GCP_TOKEN_FILE_PATH", os.path.join(ROOT_DIR, "token.json")
    )

    service = authenticate_google_drive(GCP_TOKEN_FILE_PATH)
    if not service:
        print(
            f"Was unable to authenticate with Google Drive at path {GCP_TOKEN_FILE_PATH}, if an old token.json is present, delete and re-run"
        )
    return service


def gather_valid_gdrive_files(gdrive_service):
    files = list_all_files(gdrive_service)

    if not files:
        print("No files found.")
        return {}

    organized_file_collection = categorize_files(files)

    return organized_file_collection


def process_gdrive_files(gdrive_service, organized_file_collection):
    for file_type, files_metadata in organized_file_collection.items():
        for file_metadata in files_metadata:
            process_gdrive_file(gdrive_service, file_type, file_metadata)


def main():
    gdrive_service = get_gdrive_service_object()
    organized_file_collection = gather_valid_gdrive_files(gdrive_service)
    process_gdrive_files(gdrive_service, organized_file_collection)


if __name__ == "__main__":
    main()
