# ---------------------
# IOC Classifier
# check and match for url then domain
# ---------------------
import re
from .schema import IOCType

# regex patterns
_PATTERNS = {
    # match 4 groups of 255 or 2** or 0** or 1**
    IOCType.IP: re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    ),
    IOCType.HASH_MD5: re.compile(r"^[0-9a-fA-F]{32}$"),
    IOCType.HASH_SHA256: re.compile(r"^[0-9a-fA-F]{64}$"),
    IOCType.URL: re.compile(r"^https?://", re.IGNORECASE),
    # easier to match anything but not @
    IOCType.EMAIL: re.compile(r"^[^@]+@[^@]+\.[^@]+$"),
    IOCType.DOMAIN: re.compile(
        r"^(?:[0-9a-zA-Z](?:[0-9a-zA-Z]{61}[0-9a-zA-Z])?\.)"
        r"+[a-zA-Z]{2,}$"  # ends with at least 2 chars
    ),
}


def classify_ioc(value: str) -> IOCType:
    """ Classify indicatory to IOC type"""
    value = value.strip()
    for ioc_type, pattern in _PATTERNS.items():
        if pattern.match(value):
            return ioc_type
    return IOCType.UNKNOWN
