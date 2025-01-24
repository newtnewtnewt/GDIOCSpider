import os

from gdiocspider.settings import settings_store


class DataBank:
    def load_keyword_data(self):
        keywords_to_scan_for = []
        for keyword_file_location in settings_store.KEYWORD_FILEPATHS_TO_USE:
            try:
                with open(keyword_file_location) as f:
                    keywords_to_scan_for.extend(f.read().splitlines())
            except FileNotFoundError:
                print(
                    f"Could not find keyword file at path {keyword_file_location}, ignoring."
                )
        keywords_to_scan_for = list(set(keywords_to_scan_for))
        return keywords_to_scan_for

    def load_valid_domain_endings(self):
        from gdiocspider.valid_domain_endings import VALID_TLDS

        # NOTE: we remove zip and py here. malware.py the website is indistinguishable from malware.py the domain
        # We assume it's a file, but further investigation may prove this false
        VALID_TLDS.remove("ZIP")
        VALID_TLDS.remove("PY")
        return VALID_TLDS

    def __init__(self):
        self.keyword_data = self.load_keyword_data()
        self.valid_domain_endings = self.load_valid_domain_endings()


# Craft a singleton to prevent circular imports
data_bank = DataBank()
