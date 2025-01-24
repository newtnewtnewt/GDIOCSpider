import csv
import json
from typing import List

import pandas as pd
import pymupdf4llm
from pymupdf import Document

from gdiocspider.ioc_flagger import IOCTyper
from gdiocspider.settings import settings_store


class TextFileScraperParser:
    """
    A parser for regular .txt files, python scripts, unknown files, and markdown converted from PDFs
    """

    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def check_strings_for_iocs(self, file_contents: List[str]):
        """
        Uses the IOCTyper class to check each string in the file for IOCs

        Args:
            file_contents: A list of strings, each representing a blocked string that has been split by delimiter(s)

        Returns:
            A list of dictionaries of all iocs found and their types

        """
        all_iocs = []

        for potential_ioc in file_contents:
            potential_typed_ioc = IOCTyper(
                potential_ioc, strict_mode=settings_store.IOC_TYPER_STRICT_MODE
            )
            if potential_typed_ioc.ioc_type != "Unknown":
                all_iocs.append(
                    {
                        "type": potential_typed_ioc.ioc_type,
                        "value": potential_typed_ioc.ioc_value,
                    }
                )
                print(
                    f"IOC Found in Text: Type: {potential_typed_ioc.ioc_type}, Value: {potential_typed_ioc.ioc_value}"
                )
        return all_iocs

    def extract_all_iocs(self, string_to_read=""):
        """
        Provided a file path or a string to read, this function will split the file contents by the delimiters in
        PERMITTED_DELIMITERS_TO_CHECK_AGAINST, take the remaining list of strings, and use the
        IOCTyper to find potential IOCs.

        Args:
            string_to_read: Optional parameter if we want to provide a string to split instead of reading the file directly.

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
        found_iocs = []
        with open(self.downloaded_file_path, "r") as f:
            # In case we need to search a string as is (directly inputted to the function)
            if string_to_read:
                file_contents = string_to_read
            else:
                # Read as one giant string so we can parse in multiple ways
                file_contents = f.read()
            for delimiter in settings_store.PERMITTED_DELIMITERS_TO_CHECK_AGAINST:
                file_contents = file_contents.replace(
                    delimiter, "(THIS_IS_GOING_TO_BE_SPLIT_AGAINST)"
                )
            file_contents = file_contents.split("(THIS_IS_GOING_TO_BE_SPLIT_AGAINST)")
            found_iocs = self.check_strings_for_iocs(file_contents)

        return found_iocs


class CSVFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def check_strings_for_iocs(self, row_data):
        """
        Iterates over a single CSV row split by comma and hunts for IOCs

        Args:
            row_data: A list of strings, each representing a blocked string that has been split by ','

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
        all_iocs = []
        for potential_ioc in row_data:
            potential_typed_ioc = IOCTyper(
                potential_ioc, strict_mode=settings_store.IOC_TYPER_STRICT_MODE
            )
            if potential_typed_ioc.ioc_type != "Unknown":
                all_iocs.append(
                    {
                        "type": potential_typed_ioc.ioc_type,
                        "value": potential_typed_ioc.ioc_value,
                    }
                )
                print(
                    f"IOC Found in CSV: Type: {potential_typed_ioc.ioc_type}, Value: {potential_typed_ioc.ioc_value}"
                )
        return all_iocs

    def extract_all_iocs(self):
        """
        Reads a CSV file, splits each row by comma, and passes each row to check_strings_for_iocs()

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
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
        """
        Scans through the full structure of a dictionary object and checks for IOCs in both the keys and values

        Args:
            data: A Dictionary of JSON data to be scanned for IOCs.

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
        found_iocs = []
        for key, value in data.items():
            potential_typed_key = IOCTyper(
                str(key), strict_mode=settings_store.IOC_TYPER_STRICT_MODE
            )
            if potential_typed_key.ioc_type != "Unknown":
                found_iocs.append(
                    {
                        "type": potential_typed_key.ioc_type,
                        "value": potential_typed_key.ioc_value,
                    }
                )
                print(
                    f"IOC Found in JSON Dict Key: Type: {potential_typed_key.ioc_type}, Value: {potential_typed_key.ioc_value}"
                )
            # Recursion is used here to trace through multiple nested layers at an unknown depth
            if isinstance(value, dict):
                found_iocs.extend(self.check_dict_for_iocs(value))
            elif isinstance(value, list):
                found_iocs.extend(self.check_list_for_iocs(value))
            else:
                potential_typed_value = IOCTyper(
                    str(value), strict_mode=settings_store.IOC_TYPER_STRICT_MODE
                )
                if potential_typed_value.ioc_type != "Unknown":
                    found_iocs.append(
                        {
                            "type": potential_typed_value.ioc_type,
                            "value": potential_typed_value.ioc_value,
                        }
                    )
                    print(
                        f"IOC Found in JSON Dict Value: Type: {potential_typed_value.ioc_type}, Value: {potential_typed_value.ioc_value}"
                    )
        return found_iocs

    def check_list_for_iocs(self, data):
        """
        Scans through the full structure of a List Object and checks for IOCs

        Args:
            data: A List of JSON data to be scanned for IOCs.

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
        found_iocs = []
        for item in data:
            if isinstance(item, dict):
                found_iocs.extend(self.check_dict_for_iocs(item))
            elif isinstance(item, list):
                found_iocs.extend(self.check_list_for_iocs(item))
            else:
                potential_typed_item = IOCTyper(
                    str(item), strict_mode=settings_store.IOC_TYPER_STRICT_MODE
                )
                if potential_typed_item.ioc_type != "Unknown":
                    found_iocs.append(
                        {
                            "type": potential_typed_item.ioc_type,
                            "value": potential_typed_item.ioc_value,
                        }
                    )
                    print(
                        f"IOC Found in JSON List: Type: {potential_typed_item.ioc_type}, Value: {potential_typed_item.ioc_value}"
                    )

        return found_iocs

    def extract_all_iocs(self):
        """
        Recursively crawls through the structure of a JSON file and checks for IOCs

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
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

    def check_string_for_iocs(self, cell_value):
        """
        This checks a string for any possible IOC

        Args:
            cell_value: A string representing a single cell in an XLSX file.

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
        all_iocs = []
        potential_typed_ioc = IOCTyper(
            str(cell_value), strict_mode=settings_store.IOC_TYPER_STRICT_MODE
        )
        if potential_typed_ioc.ioc_type != "Unknown":
            all_iocs.append(
                {
                    "type": potential_typed_ioc.ioc_type,
                    "value": potential_typed_ioc.ioc_value,
                }
            )
            print(
                f"IOC Found in XLSX: Type: {potential_typed_ioc.ioc_type}, Value: {potential_typed_ioc.ioc_value}"
            )
        return all_iocs

    def extract_all_iocs(self):
        """
        Process the individual tabs of an XLSX file and check each cell for IOCs

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
        found_iocs = []
        try:
            with pd.ExcelFile(self.downloaded_file_path) as xlsx_data:
                for sheet_name in xlsx_data.sheet_names:
                    sheet_df = xlsx_data.parse(sheet_name)
                    for _, row in sheet_df.iterrows():
                        for cell in row:
                            if pd.isna(cell):
                                continue
                            new_found_iocs = self.check_string_for_iocs(cell)
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
        """
        This converts a PDF into markdown, and then uses the plain text parser to extract IOCs.

        Returns:
            A list of dictionaries of all iocs found and their types.

        """
        found_iocs = []
        try:
            with Document(self.downloaded_file_path) as pymupd_doc:
                text_as_md = pymupdf4llm.to_markdown(
                    doc=pymupd_doc, show_progress=False
                )
                text_file_parser = TextFileScraperParser(
                    self.downloaded_file_path, self.file_metadata
                )
                found_iocs = text_file_parser.extract_all_iocs(
                    string_to_read=text_as_md
                )
                return found_iocs
        except Exception as e:
            print(f"Error reading PDF file: {e}")
            return found_iocs
