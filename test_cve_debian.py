from argparse import Namespace
import pytest
from cve_debian import (
    check_program_is_present,
    get_cve_details_from_json,
    get_vuln_version,
    FatalError,
)


def test_check_program_is_present():
    check_program_is_present("true", "true")
    with pytest.raises(FatalError):
        check_program_is_present("false", "false")


def test_get_cve_info_cve_2020_7247():
    args = Namespace(cve_number="2020-7247", version="bullseye", fixed_version=None)
    results = get_cve_details_from_json(args)
    assert len(results) == 1
    assert results[0]["src_package"] == "opensmtpd"
    assert results[0]["release"] == "bullseye"
    assert results[0]["fixed_version"] == "6.6.2p1-1"
    results = get_vuln_version(results)
    assert results[0]["vuln_version"] == "6.6.2p1-1~bpo10+1"


def test_get_cve_info_cve_2014_0160():
    args = Namespace(cve_number="2014-0160", version="bullseye", fixed_version=None)
    results = get_cve_details_from_json(args)
    assert len(results) == 1
    assert results[0]["src_package"] == "openssl"
    assert results[0]["release"] == "bullseye"
    assert results[0]["fixed_version"] == "1.0.1g-1"
    results = get_vuln_version(results)
    assert results[0]["vuln_version"] == "1.0.1f-1"
