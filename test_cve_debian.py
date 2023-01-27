"""
Software Name : decret (DEbian Cve REproducer Tool)
Version : 0.1
SPDX-FileCopyrightText : Copyright (c) 2023 Orange
SPDX-License-Identifier : BSD-3-Clause

This software is distributed under the BSD 3-Clause "New" or "Revised" License,
the text of which is available at https://opensource.org/licenses/BSD-3-Clause
or see the "license.txt" file for more not details.

Authors : Clément PARSSEGNY, Olivier LEVILLAIN, Maxime BELAIR, Mathieu BACOU
Software description : A tool to reproduce vulnerability affecting Debian
It gathers details from the Debian metadata and exploits from exploit-db.com
in order to build and run a vulnerable Docker container to test and
illustrate security concepts.
"""

import pytest
from decret import (
    check_program_is_present,
    prepare_browser,
    get_cve_details_from_json,
    get_cve_details_from_selenium,
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


def test_get_cve_info_cve_2014_0160(wheezy_args):
    wheezy_args.cve_number = "2014-0160"  # Heartbleed

    wheezy_args.selenium = True
    browser = prepare_browser()

    results = get_cve_details_from_selenium(browser, wheezy_args)
    assert len(results) == 1
    assert results[0]["src_package"] == "openssl"
    assert results[0]["release"] == "wheezy"
    assert results[0]["fixed_version"] == "1.0.1e-2+deb7u5"

    results = get_vuln_version(results)
    assert results[0]["vuln_version"] == "1.0.1e-2+deb7u4"

    results = get_hash_and_bin_names(wheezy_args, results)
    assert results[0]["bin_name"] == ["openssl"]
    assert results[0]["hash"] == "c901977df5fe0642d232c3c7dbd616870cbd5e98"


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
