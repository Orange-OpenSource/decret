import pytest
from cve_debian import (
    check_program_is_present,
    get_cve_details_from_json,
    get_vuln_version,
    get_hash_and_bin_names,
    CVENotFound,
    FatalError,
)


def test_check_program_is_present():
    check_program_is_present("true", "true")
    with pytest.raises(FatalError):
        check_program_is_present("false", "false")


def test_get_cve_info_cve_2020_7247(bullseye_args):
    bullseye_args.cve_number = "2020-7247"

    results = get_cve_details_from_json(bullseye_args)
    assert len(results) == 1
    assert results[0]["src_package"] == "opensmtpd"
    assert results[0]["release"] == "bullseye"
    assert results[0]["fixed_version"] == "6.6.2p1-1"

    results = get_vuln_version(results)
    assert results[0]["vuln_version"] == "6.6.2p1-1~bpo10+1"

    results = get_hash_and_bin_names(bullseye_args, results)
    assert results[0]["bin_name"] == ["opensmtpd"]
    assert results[0]["hash"] == "e2b06347249c1aadcfff7b098951b3db75ff4fa1"


def test_get_cve_info_cve_2014_0160(bullseye_args):
    bullseye_args.cve_number = "2014-0160"  # Heartbleed

    results = get_cve_details_from_json(bullseye_args)
    assert len(results) == 1
    assert results[0]["src_package"] == "openssl"
    assert results[0]["release"] == "bullseye"
    assert results[0]["fixed_version"] == "1.0.1g-1"

    results = get_vuln_version(results)
    assert results[0]["vuln_version"] == "1.0.1f-1"

    results = get_hash_and_bin_names(bullseye_args, results)
    assert results[0]["bin_name"] == ["openssl"]
    assert results[0]["hash"] == "26772bf659ee0f9fff335b5be82a29a0a34c0143"


def test_get_cve_info_from_cached_json_file(bullseye_args):
    bullseye_args.cve_number = "2020-7247"
    bullseye_args.cache_main_json_file = "test-material/opensmtpd-json-cached-data"
    results = get_cve_details_from_json(bullseye_args)
    assert len(results) == 1
    assert results[0]["src_package"] == "opensmtpd"
    assert results[0]["release"] == "bullseye"
    assert results[0]["fixed_version"] == "6.6.2p1-1"


def test_check_non_debian_cve(bullseye_args):
    # CVE-2017-0144 is Eternal Blue, so it does not affect Debian
    bullseye_args.cve_number = "2017-0144"
    with pytest.raises(CVENotFound):
        get_cve_details_from_json(bullseye_args)
