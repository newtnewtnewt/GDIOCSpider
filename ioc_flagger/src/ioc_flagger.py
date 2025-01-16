from ioc_flagger.src.indicator_checks import detect_domain_name_indicator
from ioc_flagger.src.indicator_checks import detect_email_indicator
from ioc_flagger.src.indicator_checks import detect_file_name_indicator
from ioc_flagger.src.indicator_checks import detect_file_path_indicator
from ioc_flagger.src.indicator_checks import detect_ipv4_indicator
from ioc_flagger.src.indicator_checks import detect_ipv6_indicator
from ioc_flagger.src.indicator_checks import detect_md5_indicator
from ioc_flagger.src.indicator_checks import detect_password_indicator
from ioc_flagger.src.indicator_checks import detect_registry_key_indicator
from ioc_flagger.src.indicator_checks import detect_sha1_indicator
from ioc_flagger.src.indicator_checks import detect_sha256_indicator
from ioc_flagger.src.indicator_checks import detect_sha512_indicator
from ioc_flagger.src.indicator_checks import detect_user_agent_indicator


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
            .strip()
        )

    def dynamically_interpret_type(self, ioc_value: str):
        # TODO: Allow manual disable and enable of various types
        # Applying Typing in order from easiest to detect to least easy to detect
        if detect_ipv4_indicator(ioc_value):
            return "IPv4"
        elif detect_ipv6_indicator(ioc_value):
            return "IPv6"
        elif detect_md5_indicator(ioc_value):
            return "MD5"
        elif detect_sha1_indicator(ioc_value):
            return "SHA1"
        elif detect_sha256_indicator(ioc_value):
            return "SHA256"
        elif detect_sha512_indicator(ioc_value):
            return "SHA512"
        elif detect_email_indicator(ioc_value):
            return "Email"
        elif detect_registry_key_indicator(ioc_value):
            return "Registry Key"
        elif detect_user_agent_indicator(ioc_value):
            return "User Agent"
        elif detect_domain_name_indicator(ioc_value):
            return "Domain Name"
        elif detect_file_name_indicator(ioc_value):
            return "File Name"
        elif detect_file_path_indicator(ioc_value):
            return "File Path"
        elif detect_password_indicator(ioc_value):
            return "Password"

        return "Unknown"

    def __init__(self, ioc_value: str, ioc_type: str = ""):
        # Do not perform dynamic typing if user provides a type
        if ioc_type:
            self.ioc_value = ioc_value
            self.ioc_type = ioc_type
        else:
            self.ioc_value = self.refang_indicator(ioc_value)
            self.ioc_type = self.dynamically_interpret_type(self.ioc_value)
