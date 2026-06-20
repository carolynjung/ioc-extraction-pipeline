#!/usr/bin/env python3
"""
ioc-extraction-pipeline
CLI entry point

- lookup table mapping feeds to fetch()
- specify which feeds,output path, format to use, or if dry run
- parse and resolve 'all' or part into feed list
- loop through each feed
- call fetch function in dispatch table
- collect returned IOCs into flat list
- if feed fails, log the error and continue

Usage:
    python cli.py --feeds urlhaus threatfox feodotracker --output data/output/
    python cli.py --feeds all --format json
    python cli.py --feeds urlhaus --dry-run
    python cli.py --feeds urlhaus feodotracker --format json --dry-run
"""
import argparse
import logging
from pathlib import Path
from src.ioc_pipeline.normalizer import normalize_pipeline
from src.ioc_pipeline.exporter import export_json, export_csv
from src.ioc_pipeline.feeds import urlhaus  # , threatfox, feodotracker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# using dispatch table to call functions
# urlhaus.fetch -> the function object itself stored in the dict
# urlhaus.fetch()-> calls the function right now returns list[IOC]
# result is one line handles any feed regardless of how many you add

FEED_MAP = {
    "urlhaus": urlhaus.fetch,
    # "threatfox": threatfox.fetch,
    # "feodotracker": feodotracker.fetch,
    # TODO: add otx and abuseipdb
}


def main():
    parser = argparse.ArgumentParser(
        description="Extract and normalize iocs from threat intelligence feeds."
    )
    parser.add_argument(
        "--feeds",
        nargs="+",
        choices=list(FEED_MAP.keys()) + ["all"],
        default=["all"],
        help="Which feeds to ingest (default: all)"
    )
    parser.add_argument(
        "--output",
        type=Path,  # converts str input into path automatically
        default=Path("data/output"),
        help="Output directory for JSON and CSV files"
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv", "both"],
        default="both",
        help="Output format (default: both)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",  # no arg needed either add the arg or don't
        help="Fetch and normalize but do not write output files"
    )
    args = parser.parse_args()

    # args.feeds    # ["urlhaus", "threatfox"] or ["all"]
    # args.output   # Path("data/output")
    # args.format   # "json", "csv", or "both"
    # args.dry_run  # True or False

    # feed list
    active_feeds = list(FEED_MAP.keys()) if "all" in args.feeds else args.feeds

    # ingest ioc data
    raw_iocs = []
    for feed_name in active_feeds:
        logger.info("Ingesting from %s...", feed_name)
        try:
            batch = FEED_MAP[feed_name]()
            raw_iocs.extend(batch)
        except Exception as e:
            logger.error("Feed %s failed: %s", feed_name, e)

    logger.info("Total raw IOCs: %d", len(raw_iocs))

    # normalize
    iocs = normalize_pipeline(raw_iocs)
    logger.info("Total normalized IOCs: %d", len(iocs))

    if args.dry_run:
        logger.info("Dry run — no file output")
        # Output summary instead
        from collections import Counter
        types = Counter(ioc.ioc_type.value for ioc in iocs)
        for ioc_type, count in types.most_common():
            print(f"  {ioc_type:20s}: {count:,}")
        return

    # export
    if args.format in ("json", "both"):
        export_json(iocs, args.output / "iocs.json")
    if args.format in ("csv", "both"):
        export_csv(iocs, args.output / "iocs.csv")

    print(f"\n ***** {len(iocs):,} unique IOCs written to {args.output} *****")


if __name__ == "__main__":
    main()
