"""Behavioral tests importing the real FusionSolar utility module."""

import base64
import importlib.util
from pathlib import Path
import re

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


SOURCE = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app/utils.py"
SPEC = importlib.util.spec_from_file_location("fusionsolar_utils_under_test", SOURCE)
utils = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(utils)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 0.0),
        (4, 4.0),
        (2.5, 2.5),
        ("12.5 kWh", 12.5),
        ("-3.75 W", -3.75),
        ("--", 0.0),
        ("not available", 0.0),
        ("", 0.0),
        ("0 %", 0.0),
    ],
)
def test_extract_numeric(value, expected):
    assert utils.extract_numeric(value) == expected


def test_nonce_format_and_uniqueness():
    nonces = [utils.generate_nonce() for _ in range(50)]
    assert len(set(nonces)) == len(nonces)
    assert all(re.fullmatch(r"[0-9a-f]{32}", nonce) for nonce in nonces)


def test_password_encryption_round_trip():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    encrypted = utils.encrypt_password(public_key, "secret-test-password")
    encrypted_bytes = base64.b64decode(encrypted, validate=True)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA384()),
            algorithm=hashes.SHA384(),
            label=None,
        ),
    )
    assert decrypted == b"secret-test-password"
