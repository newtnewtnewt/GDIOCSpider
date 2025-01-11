import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


class DataBank:
    def load_password_data(self):
        # TODO: Mark the markdown indicating you need to curl this
        # I'm not going to provide it
        rock_you_location = os.path.join(ROOT_DIR, "rockyou.txt")
        rock_you_list = set(
            line.strip() for line in open(rock_you_location, encoding="latin-1")
        )
        # The special character barrage is making this dicey
        rock_you_list.remove("")
        return rock_you_list

    def load_valid_domain_endings(self):
        from ioc_flagger.src.data_bank.valid_domain_endings import VALID_TLDS

        # NOTE: we remove zip and py here. malware.py the website is indistinguishable from malware.py the domain
        # We assume it's a file, but further investigation may prove this false
        VALID_TLDS.remove("ZIP")
        VALID_TLDS.remove("PY")
        return VALID_TLDS

    def __init__(self):
        self.password_data = self.load_password_data()
        self.valid_domain_endings = self.load_valid_domain_endings()
