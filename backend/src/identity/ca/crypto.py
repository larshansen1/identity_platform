"""Cryptographic utilities for certificate operations.

Provides encryption/decryption for private keys and thumbprint computation.
"""

import base64
import hashlib
import logging
import os

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Raised when a cryptographic operation fails."""

    pass


def get_encryption_key() -> bytes:
    """Load encryption key from CERT_ENCRYPTION_KEY environment variable.

    The key should be a URL-safe base64-encoded 32-byte key suitable for Fernet.

    Raises:
        CryptoError: If the key is not set or invalid.
    """
    key_str = os.environ.get("CERT_ENCRYPTION_KEY")
    if not key_str:
        raise CryptoError("CERT_ENCRYPTION_KEY environment variable not set")

    try:
        # Validate it's a valid Fernet key
        key_bytes = key_str.encode("utf-8")
        Fernet(key_bytes)  # Validates the key format
        return key_bytes
    except Exception as e:
        raise CryptoError(f"Invalid CERT_ENCRYPTION_KEY: {e}") from e


def encrypt_private_key(pem: str, key: bytes | None = None) -> str:
    """Encrypt a private key PEM string using Fernet symmetric encryption.

    Args:
        pem: The private key in PEM format.
        key: Optional encryption key. If not provided, loads from env var.

    Returns:
        Base64-encoded encrypted data.

    Raises:
        CryptoError: If encryption fails.
    """
    if key is None:
        key = get_encryption_key()

    try:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(pem.encode("utf-8"))
        return base64.urlsafe_b64encode(encrypted).decode("utf-8")
    except Exception as e:
        raise CryptoError(f"Failed to encrypt private key: {e}") from e


def decrypt_private_key(encrypted: str, key: bytes | None = None) -> str:
    """Decrypt an encrypted private key.

    Args:
        encrypted: Base64-encoded encrypted data.
        key: Optional encryption key. If not provided, loads from env var.

    Returns:
        The private key in PEM format.

    Raises:
        CryptoError: If decryption fails.
    """
    if key is None:
        key = get_encryption_key()

    try:
        fernet = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted.encode("utf-8"))
        decrypted = fernet.decrypt(encrypted_bytes)
        return decrypted.decode("utf-8")
    except Exception as e:
        raise CryptoError(f"Failed to decrypt private key: {e}") from e


def compute_thumbprint(cert_pem: str) -> str:
    """Compute SHA-256 thumbprint of a certificate.

    Args:
        cert_pem: Certificate in PEM format.

    Returns:
        Lowercase hexadecimal SHA-256 thumbprint.

    Raises:
        CryptoError: If thumbprint computation fails.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der_bytes).hexdigest().lower()
    except Exception as e:
        raise CryptoError(f"Failed to compute certificate thumbprint: {e}") from e


def generate_fernet_key() -> str:
    """Generate a new Fernet encryption key.

    Use this utility to generate a key for CERT_ENCRYPTION_KEY.

    Returns:
        A valid Fernet key as a string.
    """
    return Fernet.generate_key().decode("utf-8")
