import io
import os

from googleapiclient.http import MediaIoBaseDownload

from file_scraper.scraper_tools import (
    TextFileScraperParser,
    CSVFileScraperParser,
    PDFFileScraperParser,
    JSONFileScraperParser,
    XLSXFileScraperParser,
)


def download_file_from_gdrive(gdrive_service, file_metadata):
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
    downloaded_file_path = download_file_from_gdrive(gdrive_service, file_metadata)
    extracted_indicators = extract_indicators_from_downloaded_file(
        downloaded_file_path, file_type, file_metadata
    )
    extracted_indicators = append_count_instances_of_ioc_in_document(
        extracted_indicators
    )
    delete_downloaded_file(downloaded_file_path)
    return extracted_indicators
