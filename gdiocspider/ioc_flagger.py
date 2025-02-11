from gdiocspider.indicator_checks import dynamically_interpret_strict_type
from gdiocspider.indicator_searches import search_for_ioc_and_type
from gdiocspider.settings import settings_store


class IOCTyper:
    def refang_indicator(self, ioc_value: str):
        return (
            ioc_value.replace("hxxp", "http")
            .replace("hxxps", "https")
            .replace(",", "")
            .replace("(", "")
            .replace(")", "")
            .replace("[", "")
            .replace("]", "")
            .replace("{", "")
            .replace("}", "")
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")
            # Clean Markdown strings
            .replace("```", "")
            .replace("-----", "")
            .replace("#", "")
            .replace("comhttp", "com")
            .replace("commailto", "com")
            .strip()
        )

    def defang_indicator(self, ioc_value: str) -> str:
        # Good in 95% of cases
        ioc_value = ioc_value.replace(".", "[.]")
        return ioc_value

    def dynamically_interpret_and_strictly_type_ioc(self, ioc_value: str) -> str:
        return dynamically_interpret_strict_type(ioc_value)

    def find_and_type_ioc_in_string(self, potential_ioc_value: str) -> (str, str):
        # Applying Typing in order from easiest to detect to least easy to detect
        return search_for_ioc_and_type(potential_ioc_value)

    def __init__(self, ioc_value: str, ioc_type: str = "", strict_mode: bool = True):
        """
        This is a class used to identify IOCs from pure string values

        Args:
            ioc_value: The string representation of the potential IOC
            ioc_type: Usually blank unless you want to declare what the type is
            strict_mode: If True, the string much match a regex 'fullmatch' against the string
            If False, the string must simply contain an instance of a match of one of the IOC regexes

            WARNING: False positives will happen in either mode, just a word to the wise, finding IOCs from raw
            text with poor data context is an extremely difficult problem to solve
        """

        # Do not perform dynamic typing if user provides a type
        if ioc_type:
            self.ioc_value = ioc_value
            self.ioc_type = ioc_type
        elif strict_mode:
            self.ioc_value = self.refang_indicator(ioc_value)
            self.ioc_type = self.dynamically_interpret_and_strictly_type_ioc(
                self.ioc_value
            )
            if settings_store.DEFANG_BEFORE_EXPORT:
                self.ioc_value = self.defang_indicator(self.ioc_value)
        else:
            refanged_string = self.refang_indicator(ioc_value)
            if not refanged_string:
                self.ioc_type = "Unknown"
                self.ioc_value = ""
            else:
                self.ioc_type, self.ioc_value = self.find_and_type_ioc_in_string(
                    refanged_string
                )
                self.ioc_value = self.defang_indicator(self.ioc_value)
