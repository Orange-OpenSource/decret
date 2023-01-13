"""
Software Name : decret (DEbian Cve REproducer Tool)
Version : 0.1
SPDX-FileCopyrightText : Copyright (c) 2023 Orange
SPDX-License-Identifier : BSD-3-Clause

This software is distributed under the BSD 3-Clause "New" or "Revised" License,
the text of which is available at https://opensource.org/licenses/BSD-3-Clause
or see the "license.txt" file for more not details.

Author : Clément PARSSEGNY, Olivier LEVILLAIN, Maxime BELAIR
Software description : A tool to reproduce vulnerability affecting Debian
It gathers details from the Debian metadata and exploits from exploit-db.com
in order to build and run a vulnerable Docker container to test and
illustrate security concepts.
"""

from argparse import Namespace
import pytest


@pytest.fixture
def bullseye_args():
    return Namespace(
        release="bullseye",
        fixed_version=None,
        cache_main_json_file=None,
        bin_package=None,
    )


@pytest.fixture
def wheezy_args():
    return Namespace(
        release="wheezy",
        fixed_version=None,
        cache_main_json_file=None,
        bin_package=None,
    )
