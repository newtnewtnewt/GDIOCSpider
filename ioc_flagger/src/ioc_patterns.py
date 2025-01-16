import re

# https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
IPv4_PATTERN = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
IPv6_PATTERN = re.compile(
    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
)
MD5_PATTERN = re.compile(r"[a-fA-F0-9]{32}")
SHA1_PATTERN = re.compile(r"[a-fA-F0-9]{40}")
SHA256_PATTERN = re.compile(r"[a-fA-F0-9]{64}")
SHA512_PATTERN = re.compile(r"[a-fA-F0-9]{128}")
EMAIL_PATTERN = re.compile(
    r"\A[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z"
)
REGISTRY_PATTERN = re.compile(
    r"(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)((\\[^\0\/:*?\"<>|]+)([a-zA-Z\.-])+)*"
)
USER_AGENT_PATTERN = re.compile(
    r"[a-zA-Z][^\s]*\/[\d\.]+(\s\([^\)]+\))?(?:\s[a-zA-Z][^\s]*\/[\d\.]+(\s\([^\)]+\))?)*"
)
DOMAIN_PATTERN = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)
URL_PATTERN = re.compile(r"https?:\/\/(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?")
FILE_NAME_PATTERN = re.compile(r"(?! )[^\\/:*?\"<>|\n]+\.[a-zA-Z0-9]{1,6}")
WINDOWS_PATH_PATTERN = re.compile(
    r"[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]*"
)
LINUX_PATH_PATTERN = re.compile(r"\/(?:[^\/\0\\]+\/)*[^\/\0\\]+$")
