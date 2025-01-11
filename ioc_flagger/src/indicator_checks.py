import re

from ioc_flagger.src.data_bank.io_databank import DataBank

data_bank = DataBank()

# Precompiled regex patterns
ipv4_pattern = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\Z"
)
ipv6_pattern = re.compile(
    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
)
md5_pattern = re.compile(r"^[a-fA-F0-9]{32}$")
sha1_pattern = re.compile(r"^[a-fA-F0-9]{40}$")
sha256_pattern = re.compile(r"^[a-fA-F0-9]{64}$")
sha512_pattern = re.compile(r"^[a-fA-F0-9]{128}$")
email_pattern = re.compile(
    r"\A[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z"
)
registry_pattern = re.compile(
    r"^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)((\\[^\0\/:*?\"<>|]+)([a-zA-Z\.-])+)*$"
)
user_agent_pattern = re.compile(
    r"^[a-zA-Z][^\s]*\/[\d\.]+(\s\([^\)]+\))?(?:\s[a-zA-Z][^\s]*\/[\d\.]+(\s\([^\)]+\))?)*$"
)
domain_pattern = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
url_pattern = re.compile(r"^https?:\/\/(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?$")
file_name_pattern = re.compile(r"^[^\\/:*?\"<>|\n]+\.[a-zA-Z0-9]{1,6}$")
windows_path_pattern = re.compile(
    r"^[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]*$"
)
linux_path_pattern = re.compile(r"^\/(?:[^\/\0\\]+\/)*[^\/\0\\]+$")


def detect_ipv4_indicator(ioc_value: str) -> bool:
    return bool(ipv4_pattern.fullmatch(ioc_value))


def detect_ipv6_indicator(ioc_value: str) -> bool:
    return bool(ipv6_pattern.fullmatch(ioc_value))


def detect_md5_indicator(ioc_value: str) -> bool:
    return bool(md5_pattern.fullmatch(ioc_value))


def detect_sha1_indicator(ioc_value: str) -> bool:
    return bool(sha1_pattern.fullmatch(ioc_value))


def detect_sha256_indicator(ioc_value: str) -> bool:
    return bool(sha256_pattern.fullmatch(ioc_value))


def detect_sha512_indicator(ioc_value: str) -> bool:
    return bool(sha512_pattern.fullmatch(ioc_value))


def detect_email_indicator(ioc_value: str) -> bool:
    return bool(email_pattern.fullmatch(ioc_value))


def detect_registry_key_indicator(ioc_value: str) -> bool:
    return bool(registry_pattern.fullmatch(ioc_value))


def detect_user_agent_indicator(ioc_value: str) -> bool:
    return bool(user_agent_pattern.fullmatch(ioc_value))


def detect_password_indicator(ioc_value: str) -> bool:
    return ioc_value in data_bank.password_data


def detect_domain_name_indicator(ioc_value: str) -> bool:
    if (
        "." in ioc_value
        and bool(domain_pattern.fullmatch(ioc_value))
        and ioc_value.upper().split(".")[-1] in data_bank.valid_domain_endings
    ):
        return True
    return False


def detect_url_indicator(ioc_value: str) -> bool:
    if bool(url_pattern.fullmatch(ioc_value)):
        host_part = ioc_value.split("/")[2]
        tld = host_part.split(".")[-1].upper()
        return tld in data_bank.valid_domain_endings
    return False


def detect_file_name_indicator(ioc_value: str) -> bool:
    return bool(file_name_pattern.fullmatch(ioc_value))


def detect_file_path_indicator(ioc_value: str) -> bool:
    return bool(windows_path_pattern.fullmatch(ioc_value)) or bool(
        linux_path_pattern.fullmatch(ioc_value)
    )


# Maybe use some data to flag hostnames in here?

# Maybe brute force some usernames in here?
