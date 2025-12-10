"""Shared security utilities for API key generation and hashing."""

import base64
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Use Argon2id with secure defaults
_ph = PasswordHasher()


def generate_api_key() -> str:
    """
    Generate API key in format: idp_<32 random bytes as base64url>.

    Example: idp_x7Kj9mN2pQrStUvWxYz1A2B3C4D5E6F7...
    """
    random_bytes = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")
    return f"idp_{encoded}"


def hash_api_key(api_key: str) -> str:
    """Hash API key using Argon2id."""
    return _ph.hash(api_key)


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    """Verify API key against stored Argon2id hash."""
    try:
        _ph.verify(api_key_hash, api_key)
        return True
    except VerifyMismatchError:
        return False
