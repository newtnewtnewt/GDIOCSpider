import io
import os

from googleapiclient.http import MediaIoBaseDownload


def process_gdrive_file(gdrive_service, file_type, file_metadata):
    file_id = file_metadata.get("id")
    file_name = file_metadata.get("name", "unknown_file")
    mime_type = file_metadata.get("mimeType", "unknown_type")

    try:
        if file_id:
            request = None
            # TODO: Work on getting GSheets, Powerpoints, and Docs enabled: https://stackoverflow.com/questions/59212443/google-drive-api-with-python-not-allowing-file-download-despite-correct-scopes-b
            if mime_type == "application/vnd.google-apps.spreadsheet":
                request = gdrive_service.files().export_media(
                    fileId=file_id, mimeType="csv"
                )
            else:
                request = gdrive_service.files().get_media(fileId=file_id)

            data_dumpster_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "data_dumpster"
            )
            # Create the data_dumpster path if it doesn't exist
            os.makedirs(data_dumpster_path, exist_ok=True)

            downloaded_file_path = os.path.join(data_dumpster_path, file_name)

            with io.FileIO(downloaded_file_path, "wb") as file:
                downloader = MediaIoBaseDownload(file, request)
                done = False
                while not done:
                    _, done = downloader.next_chunk()

            print(f"Downloaded {file_name} to {downloaded_file_path}")
        else:
            print("File ID not found in file_metadata")
    except Exception as e:
        print(
            f"Failed to download file: {file_name}. Metadata: {file_metadata}. Error: {e}"
        )
