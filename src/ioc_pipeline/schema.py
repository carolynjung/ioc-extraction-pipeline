# -------------------------
# class IOC
# Updated last: 2026-06-18
# decorator adds __init__, __repr__, and __eq__
# input required: value, ioc_type, source
# default_factory to call new list or timestamp for each class instance
# bc lists are mutable shared across all class instances
# inline fxn lambda used to return UTC now in iso format
# asdict recursively converts into dict even the nested dataclasses
# bc can't serialize dataclass object to json,but can from dict
# -------------------------

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    # ---Required---
    value: str                        # the raw ioc
    ioc_type: IOCType
    source: str                       # url of feed

    # ---Optional---
    first_seen: Optional[str] = None  # timestamp
    last_seen:  Optional[str] = None  # timestamp
    tags: list[str] = field(default_factory=list)  # threats
    threat_type: Optional[str] = None
    confidence: int = 50                # scale of 1-100
    source_url: Optional[str] = None  # source link
    urlhaus_id: Optional[str] = None
    url_status: Optional[str] = None
    reporter: Optional[str] = None
    ingested_at: str = field(default_factory=lambda: datetime.utcnow().isoformat()+"Z")

    # ---  to_dict ---
    def to_dict(self) -> dict:
        d = asdict(self)
        # get str only e.g. 'ip' in  <IOCType.IP: 'ip'>
        d["ioc_type"] = self.ioc_type.value
        return d
