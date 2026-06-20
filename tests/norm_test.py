# test_normalizer.py — place at project root, run with: python test_normalizer.py

from src.ioc_pipeline.schema import IOC, IOCType
from src.ioc_pipeline.normalizer import enrich, deduplicate, normalize_pipeline


def make_ioc(**kwargs) -> IOC:
    """Helper — create an IOC with required fields plus any overrides."""
    defaults = dict(value="1.2.3.4", ioc_type=IOCType.IP, source="test")
    defaults.update(kwargs)
    return IOC(**defaults)


# ── enrich() tests ─────────────────────────────────────────────────────────────

def test_enrich_strips_ip_leading_zeros():
    iocs = [make_ioc(value="192.168.001.001", ioc_type=IOCType.IP)]
    result = enrich(iocs)
    assert result[0].value == "192.168.1.1", (
        f"Expected '192.168.1.1', got '{result[0].value}'"
    )
    print("PASS  test_enrich_strips_ip_leading_zeros")


def test_enrich_lowercases_md5():
    iocs = [make_ioc(
        value="D41D8CD98F00B204E9800998ECF8427E",
        ioc_type=IOCType.HASH_MD5
    )]
    result = enrich(iocs)
    assert result[0].value == "d41d8cd98f00b204e9800998ecf8427e", (
        f"Hash not lowercased: '{result[0].value}'"
    )
    print("PASS  test_enrich_lowercases_md5")


def test_enrich_lowercases_sha256():
    iocs = [make_ioc(
        value="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        ioc_type=IOCType.HASH_SHA256
    )]
    result = enrich(iocs)
    assert result[0].value == result[0].value.lower()
    print("PASS  test_enrich_lowercases_sha256")


def test_enrich_infers_threat_type_phishing():
    iocs = [make_ioc(
        value="http://evil.com",
        ioc_type=IOCType.URL,
        tags=["phish", "credential-harvest"],
        threat_type=None
    )]
    result = enrich(iocs)
    assert result[0].threat_type == "phishing", (
        f"Expected 'phishing', got '{result[0].threat_type}'"
    )
    print("PASS  test_enrich_infers_threat_type_phishing")


def test_enrich_infers_threat_type_c2():
    iocs = [make_ioc(tags=["botnet", "c2"], threat_type=None)]
    result = enrich(iocs)
    assert result[0].threat_type == "c2", (
        f"Expected 'c2', got '{result[0].threat_type}'"
    )
    print("PASS  test_enrich_infers_threat_type_c2")


def test_enrich_does_not_overwrite_existing_threat_type():
    iocs = [make_ioc(tags=["phishing"], threat_type="malware")]
    result = enrich(iocs)
    assert result[0].threat_type == "malware", (
        "enrich() should not overwrite an already-set threat_type"
    )
    print("PASS  test_enrich_does_not_overwrite_existing_threat_type")


def test_enrich_skips_threat_inference_when_no_tags():
    iocs = [make_ioc(tags=[], threat_type=None)]
    result = enrich(iocs)
    assert result[0].threat_type is None
    print("PASS  test_enrich_skips_threat_inference_when_no_tags")


# ── deduplicate() tests ────────────────────────────────────────────────────────

def test_deduplicate_removes_exact_duplicate():
    iocs = [
        make_ioc(value="1.2.3.4", source="urlhaus"),
        make_ioc(value="1.2.3.4", source="urlhaus"),
    ]
    result = deduplicate(iocs)
    assert len(result) == 1, f"Expected 1 unique IOC, got {len(result)}"
    print("PASS  test_deduplicate_removes_exact_duplicate")


def test_deduplicate_merges_across_sources():
    iocs = [
        make_ioc(value="1.2.3.4", source="urlhaus", confidence=70),
        make_ioc(value="1.2.3.4", source="threatfox", confidence=90),
    ]
    result = deduplicate(iocs)
    assert len(result) == 1
    assert "urlhaus" in result[0].source
    assert "threatfox" in result[0].source
    print("PASS  test_deduplicate_merges_across_sources")


def test_deduplicate_keeps_highest_confidence():
    iocs = [
        make_ioc(value="1.2.3.4", source="a", confidence=60),
        make_ioc(value="1.2.3.4", source="b", confidence=95),
    ]
    result = deduplicate(iocs)
    assert result[0].confidence == 95, (
        f"Expected confidence 95, got {result[0].confidence}"
    )
    print("PASS  test_deduplicate_keeps_highest_confidence")


def test_deduplicate_keeps_earliest_first_seen():
    iocs = [
        make_ioc(value="1.2.3.4", source="a", first_seen="2026-06-01"),
        make_ioc(value="1.2.3.4", source="b", first_seen="2025-01-01"),
    ]
    result = deduplicate(iocs)
    assert result[0].first_seen == "2025-01-01", (
        f"Expected '2025-01-01', got '{result[0].first_seen}'"
    )
    print("PASS  test_deduplicate_keeps_earliest_first_seen")


def test_deduplicate_keeps_latest_last_seen():
    iocs = [
        make_ioc(value="1.2.3.4", source="a", last_seen="2026-01-01"),
        make_ioc(value="1.2.3.4", source="b", last_seen="2026-06-18"),
    ]
    result = deduplicate(iocs)
    assert result[0].last_seen == "2026-06-18", (
        f"Expected '2026-06-18', got '{result[0].last_seen}'"
    )
    print("PASS  test_deduplicate_keeps_latest_last_seen")


def test_deduplicate_combines_tags_without_duplicates():
    iocs = [
        make_ioc(value="1.2.3.4", source="a", tags=["c2", "botnet"]),
        make_ioc(value="1.2.3.4", source="b", tags=["botnet", "mirai"]),
    ]
    result = deduplicate(iocs)
    assert sorted(result[0].tags) == ["botnet", "c2", "mirai"], (
        f"Unexpected tags: {sorted(result[0].tags)}"
    )
    print("PASS  test_deduplicate_combines_tags_without_duplicates")


def test_deduplicate_is_case_insensitive():
    iocs = [
        make_ioc(value="1.2.3.4", source="a"),
        make_ioc(value="1.2.3.4", source="b"),  # same after lower()
    ]
    result = deduplicate(iocs)
    assert len(result) == 1
    print("PASS  test_deduplicate_is_case_insensitive")


def test_deduplicate_preserves_unique_iocs():
    iocs = [
        make_ioc(value="1.2.3.4", source="a"),
        make_ioc(value="5.6.7.8", source="a"),
        make_ioc(value="9.10.11.12", source="a"),
    ]
    result = deduplicate(iocs)
    assert len(result) == 3, f"Expected 3 unique IOCs, got {len(result)}"
    print("PASS  test_deduplicate_preserves_unique_iocs")


# ── normalize_pipeline() tests ─────────────────────────────────────────────────

def test_pipeline_enriches_before_deduplicating():
    # Uppercase and lowercase versions of the same hash
    # enrich() lowercases both → deduplicate() merges them
    iocs = [
        make_ioc(
            value="D41D8CD98F00B204E9800998ECF8427E",
            ioc_type=IOCType.HASH_MD5,
            source="a"
        ),
        make_ioc(
            value="d41d8cd98f00b204e9800998ecf8427e",
            ioc_type=IOCType.HASH_MD5,
            source="b"
        ),
    ]
    result = normalize_pipeline(iocs)
    assert len(result) == 1, (
        f"Expected 1 merged IOC after pipeline, got {len(result)} — "
        "enrich() must run before deduplicate()"
    )
    print("PASS  test_pipeline_enriches_before_deduplicating")


def test_pipeline_empty_input():
    result = normalize_pipeline([])
    assert result == [], f"Expected empty list, got {result}"
    print("PASS  test_pipeline_empty_input")


# ── Runner ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)  # suppress INFO logs during tests

    tests = [
        test_enrich_strips_ip_leading_zeros,
        test_enrich_lowercases_md5,
        test_enrich_lowercases_sha256,
        test_enrich_infers_threat_type_phishing,
        test_enrich_infers_threat_type_c2,
        test_enrich_does_not_overwrite_existing_threat_type,
        test_enrich_skips_threat_inference_when_no_tags,
        test_deduplicate_removes_exact_duplicate,
        test_deduplicate_merges_across_sources,
        test_deduplicate_keeps_highest_confidence,
        test_deduplicate_keeps_earliest_first_seen,
        test_deduplicate_keeps_latest_last_seen,
        test_deduplicate_combines_tags_without_duplicates,
        test_deduplicate_is_case_insensitive,
        test_deduplicate_preserves_unique_iocs,
        test_pipeline_enriches_before_deduplicating,
        test_pipeline_empty_input,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR {test.__name__}: {type(e).__name__}: {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)
