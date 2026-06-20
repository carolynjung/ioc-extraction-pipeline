# test feed
from src.ioc_pipeline.feeds.urlhaus import fetch

iocs = fetch()
print(f"Fetched {len(iocs)} IOCs")
for ioc in iocs[5:]:
    print(ioc.value, ioc.ioc_type, ioc.confidence)
