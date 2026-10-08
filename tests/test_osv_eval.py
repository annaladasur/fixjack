from verify.authorities.osv_range import evaluate_record

RECORD = {
    "id": "GHSA-test-0000-0001",
    "aliases": ["CVE-2026-00001"],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "left-pad"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.3.0"}]}],
        },
        {
            "package": {"ecosystem": "PyPI", "name": "Requests"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.4"}]}],
        },
    ],
}


def test_inside_affected():
    r = evaluate_record(RECORD, "npm", "left-pad", "1.2.0")
    assert r.package_matched and r.in_affected and not r.is_fixed
    assert r.fixed_versions == ["1.3.0"]


def test_patched_version_is_fixed():
    r = evaluate_record(RECORD, "npm", "left-pad", "1.3.0")
    assert not r.in_affected and r.is_fixed


def test_above_patch_is_fixed():
    assert evaluate_record(RECORD, "npm", "left-pad", "2.0.0").is_fixed


def test_below_range_is_not_fixed():
    r = evaluate_record(RECORD, "npm", "left-pad", "0.9.0")
    assert not r.in_affected and not r.is_fixed


def test_pypi_name_normalization_and_zero_introduced():
    r = evaluate_record(RECORD, "PyPI", "requests", "2.30.0")
    assert r.package_matched and r.in_affected
    assert evaluate_record(RECORD, "PyPI", "requests", "2.32.4").is_fixed


def test_unlisted_package():
    r = evaluate_record(RECORD, "npm", "other", "1.0.0")
    assert not r.package_matched and not r.in_affected and not r.is_fixed
