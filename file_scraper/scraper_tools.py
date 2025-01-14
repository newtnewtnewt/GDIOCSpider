# TODO: Swap this to a settings variable
from ioc_flagger.src.ioc_flagger import IOCTyper

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


class PDFFileScraperParser:
    # https://pypi.org/project/pymupdf4llm/
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def extract_all_iocs(self):
        return {}


class XLSXFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def extract_all_iocs(self):
        return {}


class CSVFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def extract_all_iocs(self):
        return {}


class JSONFileScraperParser:
    def __init__(self, downloaded_file_path, file_metadata):
        self.downloaded_file_path = downloaded_file_path
        self.file_metadata = file_metadata

    def extract_all_iocs(self):
        return {}
