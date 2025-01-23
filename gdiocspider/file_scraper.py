import io
import os

from googleapiclient.http import MediaIoBaseDownload

from gdiocspider.scraper_tools import (
    TextFileScraperParser,
    CSVFileScraperParser,
    PDFFileScraperParser,
    JSONFileScraperParser,
    XLSXFileScraperParser,
)


def download_file_from_gdrive(gdrive_service, file_metadata):
    """
    Downloads a file from Google Drive and saves it to the data_dumpster directory. It
    will be deleted after all the indicators are extracted from it or if the file cannot be processed

    Args:
        gdrive_service: GDrive API service object used to download the files
        file_metadata: Information about the file being downloaded, including its ID, name, and MIME type.

    Returns:
        The full file path to the file that was downloaded. If the download fails, an empty string is returned.

    """
    file_id = file_metadata.get("id")
    file_name = file_metadata.get("name", "unknown_file")
    mime_type = file_metadata.get("mimeType", "unknown_type")

    try:
        if file_id:
            request = None
            if mime_type == "application/vnd.google-apps.spreadsheet":
                request = gdrive_service.files().export_media(
                    fileId=file_id,
                    mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
                file_name += ".xlsx"
            elif mime_type == "application/vnd.google-apps.presentation":
                request = gdrive_service.files().export_media(
                    fileId=file_id, mimeType="application/pdf"
                )
                file_name += ".pdf"
            elif mime_type == "application/vnd.google-apps.document":
                request = gdrive_service.files().export_media(
                    fileId=file_id, mimeType="application/pdf"
                )
                file_name += ".pdf"
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
            return downloaded_file_path
        else:
            print("File ID not found in file_metadata")
            return ""
    except Exception as e:
        print(
            f"Failed to download file: {file_name}. Metadata: {file_metadata}. Error: {e}"
        )
        return ""


def delete_downloaded_file(downloaded_file_path):
    """
    Deletes the file downloaded to data_dumpster

    Args:
        downloaded_file_path: Path to the downloaded file.

    Returns:
        N/A

    """

    try:
        if os.path.exists(downloaded_file_path):
            os.remove(downloaded_file_path)
            print(f"Deleted downloaded file: {downloaded_file_path}\n")
        else:
            print(f"File not found: {downloaded_file_path}\n")
    except Exception as e:
        print(
            f"An error occurred while trying to delete the file: {downloaded_file_path}. Error: {e}\n"
        )


def extract_indicators_from_downloaded_file(
    downloaded_file_path, file_type, file_metadata
):
    """
    Pulls indicators from a downloaded file and returns them as a list of dictionaries

    Args:
        downloaded_file_path: Where the file to be analyzed is located
        file_type: Human-readable name of the file type, such as "Text File" or "Python Script"
        file_metadata: All the associated metadata about the file, including its ID, name, and MIME type.

    Returns:
        A list of dictionaries containing the extracted indicators and their types.

    """

    extracted_indicators = {}

    if (
        file_type == "Text File"
        or file_type == "Python Script"
        or file_type == "Unknown"
    ):
        extracted_indicators = TextFileScraperParser(
            downloaded_file_path, file_metadata
        ).extract_all_iocs()

    elif file_type == "CSV File":
        extracted_indicators = CSVFileScraperParser(
            downloaded_file_path, file_metadata
        ).extract_all_iocs()

    elif (
        file_type == "PDF File"
        or file_type == "Google Slides"
        or file_type == "Google Docs"
    ):
        extracted_indicators = PDFFileScraperParser(
            downloaded_file_path, file_metadata
        ).extract_all_iocs()

    elif file_type == "JSON File":
        extracted_indicators = JSONFileScraperParser(
            downloaded_file_path, file_metadata
        ).extract_all_iocs()

    elif file_type == "Google Sheets":
        extracted_indicators = XLSXFileScraperParser(
            downloaded_file_path, file_metadata
        ).extract_all_iocs()

    return extracted_indicators


def append_count_instances_of_ioc_in_document(extracted_indicators):
    """
    A summarizer helper function that gathers quantity data before exporting to CSV,
    including the counts of each indicator/type pairing per file

    Also prints summary file to console

    Args:
        extracted_indicators: List of dictionaries containing the extracted indicators and their types.

    Returns:
        An amended version of extracted_indicators with count data appended to each indicator.

    """

    value_type_dict = {}
    value_count_dict = {}
    type_count_dict = {}
    final_indicator_records = []
    total_count = 0

    for indicator in extracted_indicators:
        value_type_dict[indicator["value"]] = indicator["type"]
        if indicator["value"] in value_count_dict:
            value_count_dict[indicator["value"]] += 1
        else:
            value_count_dict[indicator["value"]] = 1
        if indicator["type"] in type_count_dict:
            type_count_dict[indicator["type"]] += 1
            total_count += 1
        else:
            type_count_dict[indicator["type"]] = 1
            total_count += 1

    for value, type in value_type_dict.items():
        final_indicator_records.append(
            {
                "value": value,
                "type": type,
                "count": value_count_dict[value],
            }
        )

    type_count_string = ""
    for type, count in type_count_dict.items():
        type_count_string += f", {type}: {count}"
    print(f"Total IOC Count: {total_count}{type_count_string}")

    return final_indicator_records


def extract_indicators_from_gdrive_file(gdrive_service, file_type, file_metadata):
    """
    The main workhorse function for intaking a gdrive file, and outputting a list of dictionaries
    of indicator data

    Args:
        gdrive_service: The Google Drive API service object used to download the file.
        file_type: A human-readable name of the file type, such as "Text File" or "Python Script".
        file_metadata: A dictionary containing metadata about the file, including its ID, name, and MIME type.

    Returns:
        A list of dictionaries containing the extracted indicators and their types.

    """
    downloaded_file_path = download_file_from_gdrive(gdrive_service, file_metadata)
    extracted_indicators = extract_indicators_from_downloaded_file(
        downloaded_file_path, file_type, file_metadata
    )
    extracted_indicators = append_count_instances_of_ioc_in_document(
        extracted_indicators
    )
    delete_downloaded_file(downloaded_file_path)
    return extracted_indicators
