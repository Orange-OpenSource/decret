import pytest
from decret import arg_parsing, FatalError


def test_args():
    args = arg_parsing("-n 2020-7247 -r bullseye".split())
    assert args.cve_number == "2020-7247"
    assert args.release == "bullseye"

    with pytest.raises(FatalError):
        args = arg_parsing("-n NOT_A_CVE_NUMBER -r bullseye".split())

    with pytest.raises(SystemExit):
        args = arg_parsing("-n 2020-7247 -r NOT_A_RELEASE".split())
