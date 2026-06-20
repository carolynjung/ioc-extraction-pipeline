# IOC Extraction Pipeline

> Automated extraction of indicators of compromise (IOCs) daily
> from threat feeds, normalized into structured JSON and CSV.

## Architecture

Feed sources → Per-source ingestion → Normalization + dedup → JSON + CSV output → GitHub Actions auto-commit

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/ioc-extraction-pipeline
cd ioc-extraction-pipeline
pip install -r requirements.txt
python cli.py --feeds urlhaus --dry-run 
python cli.py --feeds urlhaus --output data/output/ --format json
```

## Output schema

Each IOC in `data/output/iocs.json` follows this structure:

```json
    {
      "value": "http://110.36.74.148:49905/i",
      "ioc_type": "url",
      "source": "urlhaus",
      "first_seen": "2026-05-21 00:02:16",
      "last_seen": "2026-05-21 01:09:12",
      "tags": [
        "32-bit",
        "elf",
        "mips",
        "Mozi"
      ],
      "threat_type": "malware_download",
      "confidence": 85,
      "source_url": "https://urlhaus.abuse.ch/url/3851092/",
      "urlhaus_id": "3851092",
      "url_status": "offline",
      "reporter": "geenensp",
      "ingested_at": "2026-06-20T07:07:15.962116Z"
    }
```
