from pathlib import Path

import pytest

from phish_check.extract import extract_indicators
from phish_check.parser import parse_email

SAMPLES = Path(__file__).parent / "samples"


@pytest.fixture(scope="session")
def phishing_email():
    return parse_email((SAMPLES / "phishing.eml").read_bytes())


@pytest.fixture(scope="session")
def benign_email():
    return parse_email((SAMPLES / "benign.eml").read_bytes())


@pytest.fixture(scope="session")
def phishing_indicators(phishing_email):
    return extract_indicators(phishing_email)


@pytest.fixture(scope="session")
def benign_indicators(benign_email):
    return extract_indicators(benign_email)
