import csv
import json
import logging
from pathlib import Path
from .schema import IOC

logger = logging.getLogger(__name__)


# output is a path not string; no return value
# data/output/iocs.json
# convert iocs to dicts, serialize as indented json, log number of iocs
def export_json(iocs: list[IOC], output_path: Path) -> None:
    """ Export iocs to json """
    # create dirs if doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # count is num items
    # example output
    # {
    #   "count": 2891,
    #   "iocs": [
    #     { "value": "1.1.1.1", "ioc_type": "ip", ... },
    #     { "value": "bad.com", "ioc_type": "domain", ... }
    #   ]
    # }
    data = {
        "count": len(iocs),
        "iocs": [ioc.to_dict() for ioc in iocs]
    }

    # 'with' also closes the file handler -> f.close()
    # utf-8 ascii encoding for texts;without it causes mess of non-ascii
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Exported %d IOCs to %s", len(iocs), output_path)


# output is a path not string; no return value
# data/output/iocs.csv
def export_csv(iocs: list[IOC], output_path: Path) -> None:
    """Export to csv"""
    # create dirs if doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not iocs:
        logger.warning("No iocs to export to csv")
        return

    fieldnames = list(iocs[0].to_dict().keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ioc in iocs:
            row = ioc.to_dict()
            row["tags"] = "|".join(row["tags"])  # flatten the list for csvs
            writer.writerow(row)
    logger.info("Exported %d IOCs to %s", len(iocs), output_path)
