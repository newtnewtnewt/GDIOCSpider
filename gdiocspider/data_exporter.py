import csv

from gdiocspider.settings import settings_store


def export_all_indicator_data_to_csv(indicator_data):
    """
    The final stage that writes all the data collected from scanning the GDrive
    into a CSV file.

    Args:
        indicator_data: A dictionary compromised of all indicators discovered and related file metadata

    Returns:
        N/A

    """

    # Define the CSV file header
    header = [
        "Indicator Value",
        "Indicator Type",
        "Count",
        "File Name",
        "File Path",
        "File Type",
        "File ID",
        "File Size",
    ]

    # Open the output CSV file
    with open(
        settings_store.output_file_path, mode="w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        writer.writerow(header)  # Write the header row

        # Iterate over each record in the provided JSON object
        for record in indicator_data:
            file_metadata = record["file_metadata"]
            file_name = file_metadata.get("name", "")
            file_type = record.get("file_type", "")
            file_id = file_metadata.get("id", "")
            file_path = file_metadata.get("path", "")
            file_size = file_metadata.get("size", "")

            # Iterate through all indicators for the current file
            for indicator in record.get("all_indicators", []):
                indicator_type = indicator.get("type", "")
                indicator_value = indicator.get("value", "")
                indicator_count = indicator.get("count", 0)

                # Write a row for each indicator
                writer.writerow(
                    [
                        indicator_value,
                        indicator_type,
                        indicator_count,
                        file_name,
                        file_path,
                        file_type,
                        file_id,
                        file_size,
                    ]
                )

    print(
        f"DONE! Finished exporting all indicator data to {settings_store.output_file_path}"
    )
