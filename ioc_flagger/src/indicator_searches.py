import re
import regex as rex

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


def _search_for_match_in_string(ioc_pattern: re.Pattern, ioc_value: str) -> (bool, str):
    attempted_match = re.search(ioc_pattern, ioc_value)
    if attempted_match:
        found_ioc = attempted_match.group(0)
        return True, found_ioc
    return False, ""


def find_ipv4_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(IPv4_PATTERN, ioc_value)


def find_ipv6_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(IPv6_PATTERN, ioc_value)


def find_md5_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(MD5_PATTERN, ioc_value)


def find_sha1_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(SHA1_PATTERN, ioc_value)


def find_sha256_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(SHA256_PATTERN, ioc_value)


def find_sha512_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(SHA512_PATTERN, ioc_value)


def find_email_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(EMAIL_PATTERN, ioc_value)


def find_registry_key_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(REGISTRY_PATTERN, ioc_value)


def find_user_agent_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(USER_AGENT_PATTERN, ioc_value)


def find_password_indicator(ioc_value: str) -> (bool, str):
    for password in data_bank.password_data:
        if password in ioc_value:
            return True, password
    return False, ""


def find_domain_name_indicator(ioc_value: str) -> (bool, str):
    if "." in ioc_value:
        match_found, matching_string = _search_for_match_in_string(
            DOMAIN_PATTERN, ioc_value
        )
        if matching_string:
            if matching_string.upper().split(".")[-1] in data_bank.valid_domain_endings:
                return match_found, matching_string
    return False, ""


def find_url_indicator(ioc_value: str) -> (bool, str):
    match_found, matching_string = _search_for_match_in_string(URL_PATTERN, ioc_value)
    if matching_string:
        host_part = matching_string.split("/")[2]
        tld = host_part.split(".")[-1].upper()
        if tld in data_bank.valid_domain_endings:
            return match_found, matching_string
    return False, ""


def find_file_name_indicator(ioc_value: str) -> (bool, str):
    return _search_for_match_in_string(FILE_NAME_PATTERN, ioc_value)


def find_file_path_indicator(ioc_value: str) -> (bool, str):
    match_found, matching_string = _search_for_match_in_string(
        WINDOWS_PATH_PATTERN, ioc_value
    )
    if match_found:
        return True, matching_string
    match_found, matching_string = _search_for_match_in_string(
        LINUX_PATH_PATTERN, ioc_value
    )
    return match_found, matching_string
