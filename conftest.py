from argparse import Namespace
import pytest


@pytest.fixture
def bullseye_args():
    return Namespace(
        version="bullseye",
        fixed_version=None,
        cache_main_json_file=None,
        bin_package=None,
    )


@pytest.fixture
def wheezy_args():
    return Namespace(
        version="wheezy",
        fixed_version=None,
        cache_main_json_file=None,
        bin_package=None,
    )
