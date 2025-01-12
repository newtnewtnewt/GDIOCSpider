from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
import os

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


def list_all_files(service):
    """
    List all files in the user's Google Drive.

    Args:
        service: Google Drive API service object.

    Returns:
        List of files (dict with 'id' and 'name').
    """
    try:
        results = []
        page_token = None

        while True:
            response = (
                service.files()
                .list(
                    pageSize=1000,
                    fields="nextPageToken, files(id, name, mimeType, size)",
                    pageToken=page_token,
                )
                .execute()
            )

            results.extend(response.get("files", []))
            page_token = response.get("nextPageToken", None)

            if not page_token:
                break

        return results

    except HttpError as error:
        print(f"An error occurred: {error}")
        return []


def display_files(files):
    """
    Display files and allow user selection.

    Args:
        files (list): List of files to display.

    Returns:
        List of selected file IDs.
    """
    print("\nAvailable Files:")
    selected_ids = []

    for i, file in enumerate(files):
        size = file.get("size", "Unknown")
        print(
            f"[{i}] {file['name']} (ID: {file['id']}, Type: {file['mimeType']}, Size: {size} bytes)"
        )

    choices = input("\nEnter the indices of files to select (comma-separated): ")

    try:
        indices = [int(x.strip()) for x in choices.split(",")]
        selected_ids = [files[i]["id"] for i in indices if i < len(files)]
    except ValueError:
        print("Invalid input. Please use numeric indices.")

    return selected_ids


def main():
    ROOT_DIR = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    GCP_TOKEN_FILE_PATH = os.getenv(
        "GCP_TOKEN_FILE_PATH", os.path.join(ROOT_DIR, "token.json")
    )
    print(GCP_TOKEN_FILE_PATH)

    service = authenticate_google_drive(GCP_TOKEN_FILE_PATH)
    if not service:
        return

    files = list_all_files(service)

    if not files:
        print("No files found.")
        return

    selected_ids = display_files(files)

    print("\nSelected File IDs:")
    print(selected_ids)


if __name__ == "__main__":
    main()
