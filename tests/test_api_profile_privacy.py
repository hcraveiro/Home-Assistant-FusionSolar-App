"""Keep the curated response corpus free of raw HAR/auth/device identities."""

import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parent / "fixtures" / "api_profiles"
RESPONSES = ROOT / "responses"
FORBIDDEN_KEYS = {
    "authorization", "cookie", "cookies", "set-cookie", "roarand",
    "password", "passwd", "access_token", "refresh_token", "dpsession",
    "email", "username",
}
IDENTITY_KEYS = {"dn", "parentdn", "dnid", "sn", "serialnumber", "stationdn"}


def walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key.lower(), item
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def test_no_raw_har_files_in_profile_corpus():
    assert not [p for p in ROOT.rglob("*") if ".har" in p.name.lower()]


@pytest.mark.parametrize("path", sorted(RESPONSES.glob("*.json")), ids=lambda p: p.stem)
def test_curated_responses_use_only_fictional_identities_and_no_auth(path):
    body = json.loads(path.read_text(encoding="utf-8"))
    for key, value in walk(body):
        assert key not in FORBIDDEN_KEYS, f"Forbidden auth/personal field: {key} in {path.name}"
        if key in IDENTITY_KEYS:
            assert isinstance(value, str) and value.startswith("MOCK_"), (
                f"Non-fictional identifier field: {key} in {path.name}"
            )
