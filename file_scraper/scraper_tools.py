import csv
import json

import pandas as pd
import pymupdf4llm

from ioc_flagger.src.ioc_flagger import IOCTyper

# TODO: Swap this to a settings variable
PERMITTED_DELIMITERS_TO_CHECK_AGAINST = [",", "\n", "\r", ":", "|", " "]


class TextFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def check_strings_for_iocs(self, file_contents, delimiter):
        all_iocs = []
        for potential_ioc in file_contents.split(delimiter):
            potential_typed_ioc = IOCTyper(potential_ioc)
            if potential_typed_ioc.ioc_type != "Unknown":
                all_iocs.append(potential_typed_ioc.ioc_type)
                print(
                    f"IOC Found: Type: {potential_typed_ioc.ioc_type}, Value: {potential_typed_ioc.ioc_value}"
                )
        return all_iocs

    def extract_all_iocs(self):
        found_iocs = []
        with open(self.downloaded_file_path, "r") as f:
            # Read as one giant string so we can parse in multiple ways
            file_contents = f.read()
            for delimiter in PERMITTED_DELIMITERS_TO_CHECK_AGAINST:
                if delimiter in file_contents:
                    new_found_iocs = self.check_strings_for_iocs(
                        file_contents, delimiter
                    )
                    if new_found_iocs:
                        found_iocs.extend(new_found_iocs)

                    return file_contents.split(delimiter)

        return found_iocs


class CSVFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def check_strings_for_iocs(self, row_data):
        all_iocs = []
        for potential_ioc in row_data:
            potential_typed_ioc = IOCTyper(potential_ioc)
            if potential_typed_ioc.ioc_type != "Unknown":
                all_iocs.append(potential_typed_ioc.ioc_type)
                print(
                    f"IOC Found: Type: {potential_typed_ioc.ioc_type}, Value: {potential_typed_ioc.ioc_value}"
                )
        return all_iocs

    def extract_all_iocs(self):
        found_iocs = []
        with open(self.downloaded_file_path, "r", newline="") as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                new_found_iocs = self.check_strings_for_iocs(row)
                if new_found_iocs:
                    found_iocs.extend(new_found_iocs)

        return found_iocs


class JSONFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def check_dict_for_iocs(self, data):
        found_iocs = []
        for key, value in data.items():
            potential_typed_key = IOCTyper(str(key))
            if potential_typed_key.ioc_type != "Unknown":
                found_iocs.append(potential_typed_key.ioc_type)
                print(
                    f"IOC Found in Key: Type: {potential_typed_key.ioc_type}, Value: {potential_typed_key.ioc_value}"
                )
            potential_typed_value = IOCTyper(str(value))
            if potential_typed_value.ioc_type != "Unknown":
                found_iocs.append(potential_typed_value.ioc_type)
                print(
                    f"IOC Found in Value: Type: {potential_typed_value.ioc_type}, Value: {potential_typed_value.ioc_value}"
                )
            if isinstance(value, dict):
                found_iocs.extend(self.check_dict_for_iocs(value))
            elif isinstance(value, list):
                found_iocs.extend(self.check_list_for_iocs(value))
        return found_iocs

    def check_list_for_iocs(self, data):
        found_iocs = []
        for item in data:
            potential_typed_item = IOCTyper(str(item))
            if potential_typed_item.ioc_type != "Unknown":
                found_iocs.append(potential_typed_item.ioc_type)
                print(
                    f"IOC Found in List: Type: {potential_typed_item.ioc_type}, Value: {potential_typed_item.ioc_value}"
                )
            if isinstance(item, dict):
                found_iocs.extend(self.check_dict_for_iocs(item))
            elif isinstance(item, list):
                found_iocs.extend(self.check_list_for_iocs(item))
        return found_iocs

    def extract_all_iocs(self):
        found_iocs = []
        try:
            with open(self.downloaded_file_path, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    found_iocs.extend(self.check_dict_for_iocs(data))
                elif isinstance(data, list):
                    found_iocs.extend(self.check_list_for_iocs(data))
        except Exception as e:
            print(f"Error reading JSON file: {e}")
        return found_iocs


class XLSXFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def check_strings_for_iocs(self, cell_value):
        all_iocs = []
        potential_typed_ioc = IOCTyper(str(cell_value))
        if potential_typed_ioc.ioc_type != "Unknown":
            all_iocs.append(potential_typed_ioc.ioc_type)
            print(
                f"IOC Found: Type: {potential_typed_ioc.ioc_type}, Value: {potential_typed_ioc.ioc_value}"
            )
        return all_iocs

    def extract_all_iocs(self):
        found_iocs = []
        try:
            with pd.ExcelFile(self.downloaded_file_path) as xlsx_data:
                for sheet_name in xlsx_data.sheet_names:
                    sheet_df = xlsx_data.parse(sheet_name)
                    for _, row in sheet_df.iterrows():
                        for cell in row:
                            if pd.isna(cell):
                                continue
                            new_found_iocs = self.check_strings_for_iocs(cell)
                            if new_found_iocs:
                                found_iocs.extend(new_found_iocs)
        except Exception as e:
            print(f"Error reading XLSX file: {e}")
        return found_iocs


class PDFFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def extract_all_iocs(self):
        # https://pypi.org/project/pymupdf4llm/
        # TODO: This file is refusing to close, so it can't be deleted
        md_text = pymupdf4llm.to_markdown(
            self.downloaded_file_path, show_progress=False
        )
        print("TRY THIS AGAIN")
        print(type(md_text))
        return {}
