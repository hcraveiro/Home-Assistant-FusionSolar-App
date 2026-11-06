"""Utils functions."""

import base64
import math
import re
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_nonce() -> str:
    return ''.join(secrets.token_hex(1) for _ in range(16))
    
def encrypt_password(pub_key_pem, password) -> str:
    # Load public key
    public_key = serialization.load_pem_public_key(pub_key_pem.encode())
        
    # Encrypt password
    encrypted_password = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA384()),
            algorithm=hashes.SHA384(),
            label=None
        )
    )
        
    return base64.b64encode(encrypted_password).decode()
    
# Explicit suffixes are dimensional, not decoration. Only W -> kW and Wh ->
# kWh scaling is supported; other telemetry must match its canonical unit.
_NUMERIC_UNIT_FACTORS = {
    "": {"": 1},
    "kW": {"kw": 1, "w": 0.001},
    "kWh": {"kwh": 1, "wh": 0.001},
    # Battery module fixtures also use the unadorned Celsius suffix C.
    "°C": {"°C": 1, "C": 1},
    **{unit: {unit: 1} for unit in ("%", "V", "A", "Hz", "MΩ", "var", "kg", "min")},
}
_NUMERIC_RE = re.compile(
    r"\s*([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)\s*([^\s]*)\s*"
)


def extract_numeric(value_with_unit, unit: str = "", *, default_unit: str | None = None) -> float | None:
    """Return a finite reading in ``unit``, or None (never a fabricated zero).

    Bare JSON numbers/numeric strings use ``default_unit`` (otherwise ``unit``).
    An explicit suffix overrides that default and must match the dimension.
    Power/energy suffixes are case-insensitive for compatibility with existing
    readers. No grouping separators, trailing text or speculative vendor units.
    Rounding and domain-specific discovery policies belong to the caller.
    """
    if isinstance(value_with_unit, bool) or not isinstance(value_with_unit, (int, float, str)):
        return None
    suffix = default_unit if default_unit is not None else unit
    if isinstance(value_with_unit, str):
        match = _NUMERIC_RE.fullmatch(value_with_unit)
        if match is None:
            return None
        raw, explicit_unit = match.groups()
        suffix = explicit_unit or suffix
    else:
        raw = value_with_unit
    if unit in ("kW", "kWh"):
        suffix = suffix.lower()
    factor = _NUMERIC_UNIT_FACTORS.get(unit, {}).get(suffix)
    if factor is None:
        return None
    try:
        value = float(raw)
        if not math.isfinite(value):
            return None
        value *= factor
    except (ValueError, TypeError, OverflowError):
        return None
    return value if math.isfinite(value) else None