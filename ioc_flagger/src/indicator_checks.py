import re


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
    return False


def detect_user_agent_indicator(ioc_value: str) -> bool:
    return False


def detect_username_indicator(ioc_value: str) -> bool:
    return False


def detect_password_indicator(ioc_value: str) -> bool:
    return False


def detect_domain_name_indicator(ioc_value: str) -> bool:
    return False


def detect_file_name_indicator(ioc_value: str) -> bool:
    return False


def detect_file_path_indicator(ioc_value: str) -> bool:
    return False
