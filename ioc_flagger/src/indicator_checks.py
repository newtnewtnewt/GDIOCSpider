import re

from ioc_flagger.src.data_bank.io_databank import DataBank

data_bank = DataBank()


def detect_ipv4_indicator(ioc_value: str) -> bool:
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\Z"
    return bool(re.fullmatch(ipv4_pattern, ioc_value))


def detect_ipv6_indicator(ioc_value: str) -> bool:
    # https://stackoverflow.com/a/17871737
    ipv6_pattern = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    return bool(re.fullmatch(ipv6_pattern, ioc_value))


def detect_md5_indicator(ioc_value: str) -> bool:
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    return bool(re.fullmatch(md5_pattern, ioc_value))


def detect_sha1_indicator(ioc_value: str) -> bool:
    sha1_pattern = r"^[a-fA-F0-9]{40}$"
    return bool(re.fullmatch(sha1_pattern, ioc_value))


def detect_sha256_indicator(ioc_value: str) -> bool:
    sha256_pattern = r"^[a-fA-F0-9]{64}$"
    return bool(re.fullmatch(sha256_pattern, ioc_value))


def detect_sha512_indicator(ioc_value: str) -> bool:
    sha512_pattern = r"^[a-fA-F0-9]{128}$"
    return bool(re.fullmatch(sha512_pattern, ioc_value))


def detect_email_indicator(ioc_value: str) -> bool:
    # https://www.regular-expressions.info/email.html
    email_pattern = r"\A[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z"
    return bool(re.fullmatch(email_pattern, ioc_value))


def detect_registry_key_indicator(ioc_value: str) -> bool:
    registry_pattern = r"^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)((\\[^\0\/:*?\"<>|]+)([a-zA-Z\.-])+)*$"
    return bool(re.fullmatch(registry_pattern, ioc_value))


def detect_user_agent_indicator(ioc_value: str) -> bool:
    user_agent_pattern = r"^[a-zA-Z][^\s]*\/[\d\.]+(\s\([^\)]+\))?(?:\s[a-zA-Z][^\s]*\/[\d\.]+(\s\([^\)]+\))?)*$"
    return bool(re.fullmatch(user_agent_pattern, ioc_value))


# TODO: Maybe try a username brute force at some point


def detect_password_indicator(ioc_value: str) -> bool:
    return ioc_value in data_bank.password_data


def detect_domain_name_indicator(ioc_value: str) -> bool:
    domain_pattern = (
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if (
        "." in ioc_value
        and bool(re.fullmatch(domain_pattern, ioc_value))
        and ioc_value.upper().split(".")[-1] in data_bank.valid_domain_endings
    ):
        return True
    return False


def detect_url_indicator(ioc_value: str) -> bool:
    return False


def detect_file_name_indicator(ioc_value: str) -> bool:
    return False


def detect_file_path_indicator(ioc_value: str) -> bool:
    return False
