"""
Software Name : decret (DEbian Cve REproducer Tool)
Version : 0.1
SPDX-FileCopyrightText : Copyright (c) 2023-2025 Orange
SPDX-License-Identifier : BSD-3-Clause

This software is distributed under the BSD 3-Clause "New" or "Revised" License,
the text of which is available at https://opensource.org/licenses/BSD-3-Clause
or see the "license.txt" file for more not details.

Authors : Clément PARSSEGNY, Olivier LEVILLAIN, Maxime BELAIR, Mathieu BACOU,
Nicolas DEJON
Software description : A tool to reproduce vulnerability affecting Debian
It gathers details from the Debian metadata and exploits from exploit-db.com
in order to build and run a vulnerable Docker container to test and
illustrate security concepts.
"""

import pytest
from decret.decret import arg_parsing, FatalError


def test_args():
    args = arg_parsing("-n 2020-7247 -r bullseye".split())
    assert args.cve_number == "2020-7247"
    assert args.release == "bullseye"

    with pytest.raises(FatalError):
        args = arg_parsing("-n NOT_A_CVE_NUMBER -r bullseye".split())

    with pytest.raises(SystemExit):
        args = arg_parsing("-n 2020-7247 -r NOT_A_RELEASE".split())
