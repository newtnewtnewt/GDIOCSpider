# For use with 1-1 strict matches of exactly what the IOC is, not searching within the string

from ioc_flagger.src.data_bank.io_databank import DataBank

data_bank = DataBank()

from ioc_flagger.src.ioc_patterns import (
    IPv4_PATTERN,
    IPv6_PATTERN,
    MD5_PATTERN,
    SHA1_PATTERN,
    SHA256_PATTERN,
    SHA512_PATTERN,
    EMAIL_PATTERN,
    REGISTRY_PATTERN,
    USER_AGENT_PATTERN,
    DOMAIN_PATTERN,
    URL_PATTERN,
    FILE_NAME_PATTERN,
    WINDOWS_PATH_PATTERN,
    LINUX_PATH_PATTERN,
)


def detect_ipv4_indicator(ioc_value: str) -> bool:
    return bool(IPv4_PATTERN.fullmatch(ioc_value))


def detect_ipv6_indicator(ioc_value: str) -> bool:
    return bool(IPv6_PATTERN.fullmatch(ioc_value))


def detect_md5_indicator(ioc_value: str) -> bool:
    return bool(MD5_PATTERN.fullmatch(ioc_value))


def detect_sha1_indicator(ioc_value: str) -> bool:
    return bool(SHA1_PATTERN.fullmatch(ioc_value))


def detect_sha256_indicator(ioc_value: str) -> bool:
    return bool(SHA256_PATTERN.fullmatch(ioc_value))


def detect_sha512_indicator(ioc_value: str) -> bool:
    return bool(SHA512_PATTERN.fullmatch(ioc_value))


def detect_email_indicator(ioc_value: str) -> bool:
    return bool(EMAIL_PATTERN.fullmatch(ioc_value))


def detect_registry_key_indicator(ioc_value: str) -> bool:
    return bool(REGISTRY_PATTERN.fullmatch(ioc_value))


def detect_user_agent_indicator(ioc_value: str) -> bool:
    return bool(USER_AGENT_PATTERN.fullmatch(ioc_value))


def detect_password_indicator(ioc_value: str) -> bool:
    return ioc_value in data_bank.password_data


def detect_domain_name_indicator(ioc_value: str) -> bool:
    if (
        "." in ioc_value
        and bool(DOMAIN_PATTERN.fullmatch(ioc_value))
        and ioc_value.upper().split(".")[-1] in data_bank.valid_domain_endings
    ):
        return True
    return False


def detect_url_indicator(ioc_value: str) -> bool:
    if bool(URL_PATTERN.fullmatch(ioc_value)):
        host_part = ioc_value.split("/")[2]
        tld = host_part.split(".")[-1].upper()
        return tld in data_bank.valid_domain_endings
    return False


def detect_file_name_indicator(ioc_value: str) -> bool:
    return bool(FILE_NAME_PATTERN.fullmatch(ioc_value))


def detect_file_path_indicator(ioc_value: str) -> bool:
    return bool(WINDOWS_PATH_PATTERN.fullmatch(ioc_value)) or bool(
        LINUX_PATH_PATTERN.fullmatch(ioc_value)
    )


# Maybe use some data to flag hostnames in here?

# Maybe brute force some usernames in here?
