"""Utils functions."""

import base64
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
    
def extract_numeric(value_with_unit) -> float:
    """Extract a numeric value from either a number or a string with units."""
    if value_with_unit is None:
        return 0.0

    if isinstance(value_with_unit, (int, float)):
        return float(value_with_unit)

    try:
        return float(str(value_with_unit).split()[0])
    except (ValueError, AttributeError, IndexError, TypeError):
        return 0.0