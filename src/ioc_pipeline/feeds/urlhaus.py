import csv
import logging
import requests
from ..schema import IOC, IOCType

logger = logging.getLogger(__name__)
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


# example entry
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
# "3867108","2026-06-18 23:00:12","http://42.227.202.44:44265/bin.sh",
# "online","2026-06-18 23:00:12","malware_download","32-bit,elf,mips,Mozi",
# "https://urlhaus.abuse.ch/url/3867108/","geenensp"
def fetch() -> list[IOC]:
    """Fetch recent malicious URLs from URLhaus (abuse.ch). No API key required."""
    iocs: list[IOC] = []
    try:
        response = requests.get(URLHAUS_CSV_URL, timeout=30)
        response.raise_for_status()

        header_line = None
        data_lines = []

        for line in response.text.splitlines():
            stripped = line.strip()
            if stripped.startswith("# id,"):
                # header embedded in comment;strip 2 chars "# "
                header_line = stripped[2:]
            elif not stripped.startswith("#") and stripped:
                data_lines.append(stripped)

        if not header_line:
            logger.error("URLhaus: could not find header line in CSV response")
            return iocs

        if not data_lines:
            logger.warning("URLhaus: header found but no data rows parsed")
            return iocs

        reader = csv.DictReader(data_lines, fieldnames=header_line.split(","))

        for row in reader:
            url = row.get("url", "").strip()
            if not url:
                continue

            raw_tags = row.get("tags", "").strip()
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []

            iocs.append(IOC(
                value=url,
                ioc_type=IOCType.URL,
                source="urlhaus",
                first_seen=row.get("dateadded"),
                last_seen=row.get("last_online"),   # new column
                tags=tags,
                threat_type=row.get("threat"),
                confidence=85,
                source_url=row.get("urlhaus_link"),
                urlhaus_id=row.get("id"),
                url_status=row.get("url_status"),
                reporter=row.get("reporter"),
            ))

    except requests.RequestException as e:
        logger.error("URLhaus fetch failed: %s", e)

    logger.info("URLhaus: fetched %d IOCs", len(iocs))
    return iocs


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    iocs = fetch()
    # print head 5
    for ioc in iocs[5:]:
        print(f"  {ioc.value[:55]:55s}  last_online={ioc.last_seen}  tags={ioc.tags}")
