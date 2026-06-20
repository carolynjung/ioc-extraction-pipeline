import logging
from .schema import IOC, IOCType

logger = logging.getLogger(__name__)


def deduplicate(iocs: list[IOC]) -> list[IOC]:
    """ Dedup iocs; first_seen & last_seen, merge tags, >confidence """
    seen: dict[str, IOC] = {}

    for ioc in iocs:
        # lower and strip to prevent dups
        key = ioc.value.lower().strip()

        # separate if seen before
        if key not in seen:
            seen[key] = ioc
        else:
            existing = seen[key]
            # keep earliest first_seen
            if ioc.first_seen and existing.first_seen:
                existing.first_seen = min(ioc.first_seen, existing.first_seen)
            # keep latest last_seen
            if ioc.last_seen:
                if not existing.last_seen or ioc.last_seen > existing.last_seen:
                    existing.last_seen = ioc.last_seen
            # combine tags; sets have unique values
            existing.tags = list(set(existing.tags + ioc.tags))
            # keep highest confidence
            existing.confidence = max(existing.confidence, ioc.confidence)
            # store all sources
            existing.source = f"{existing.source},{ioc.source}"

    deduped = list(seen.values())
    logger.info(
        "Deduplication: %d raw → %d unique IOCs",
        len(iocs), len(deduped)
    )
    return deduped


def enrich(iocs: list[IOC]) -> list[IOC]:
    """ adds threat types and normalizes values """
    for ioc in iocs:
        # strip tracking parameters and lowercase
        if ioc.ioc_type == IOCType.URL:
            ioc.value = ioc.value.strip()

        # strip leading zeros
        if ioc.ioc_type == IOCType.IP:
            try:
                parts = ioc.value.split(".")
                ioc.value = ".".join(str(int(p)) for p in parts)
            except ValueError:
                pass

        # lowercase
        if ioc.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA256):
            ioc.value = ioc.value.lower()

        # lowercase
        # normalize similar threat types to same
        if not ioc.threat_type and ioc.tags:
            tag_lower = [t.lower() for t in ioc.tags]
            if any(t in tag_lower for t in ["phishing", "phish"]):
                ioc.threat_type = "phishing"
            elif any(t in tag_lower for t in ["malware", "rat", "trojan"]):
                ioc.threat_type = "malware"
            elif any(t in tag_lower for t in ["c2", "botnet", "c&c"]):
                ioc.threat_type = "c2"
    return iocs


def normalize_pipeline(raw_iocs: list[IOC]) -> list[IOC]:
    """ Enrich then deduplicate """
    enriched = enrich(raw_iocs)
    return deduplicate(enriched)


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    # Tests
    raw_iocs = [
        # 1. IP with leading zeros — enrich() should strip them
        IOC(value="192.168.001.001", ioc_type=IOCType.IP, source="test"),

        # 2. Same IP, different source — deduplicate() should merge
        IOC(value="192.168.1.1", ioc_type=IOCType.IP, source="threatfox",
            confidence=90, tags=["c2"], first_seen="2026-01-01",
            last_seen="2026-06-01"),

        # 3. First entry for that IP with earlier first_seen
        IOC(value="192.168.001.001", ioc_type=IOCType.IP, source="feodotracker",
            confidence=75, tags=["botnet"], first_seen="2025-12-01",
            last_seen="2026-05-01"),

        # 4. Hash in uppercase — enrich() should lowercase it
        IOC(value="D41D8CD98F00B204E9800998ECF8427E",
            ioc_type=IOCType.HASH_MD5, source="otx"),

        # 5. Same hash lowercase — deduplicate() should merge with #4
        IOC(value="d41d8cd98f00b204e9800998ecf8427e",
            ioc_type=IOCType.HASH_MD5, source="threatfox", confidence=80),

        # 6. URL with no threat_type but tags — enrich() should infer threat_type
        IOC(value="http://evil.com/payload", ioc_type=IOCType.URL,
            source="urlhaus", tags=["phishing", "credential-harvest"]),

        # 7. IOC with no threat_type and c2 tags
        IOC(value="10.0.0.1", ioc_type=IOCType.IP,
            source="feodotracker", tags=["c2", "botnet"]),
    ]

    print("=" * 60)
    print(f"INPUT: {len(raw_iocs)} raw IOCs")
    print("=" * 60)
    for ioc in raw_iocs:
        print(f"  [{ioc.source:12s}] {ioc.ioc_type.value:10s}  {ioc.value}")

    # ── Run pipeline ───────────────────────────────────────────────
    result = normalize_pipeline(raw_iocs)

    print()
    print("=" * 60)
    print(f"OUTPUT: {len(result)} unique IOCs after normalize_pipeline()")
    print("=" * 60)
    for ioc in result:
        print(f"  source={ioc.source}")
        print(f"  value={ioc.value}")
        print(f"  type={ioc.ioc_type.value}")
        print(f"  confidence={ioc.confidence}")
        print(f"  threat_type={ioc.threat_type}")
        print(f"  tags={ioc.tags}")
        print(f"  first_seen={ioc.first_seen}")
        print(f"  last_seen={ioc.last_seen}")
        print()
