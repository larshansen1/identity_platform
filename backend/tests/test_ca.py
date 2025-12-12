"""Unit tests for CA module components."""

from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from identity.ca.certificate_generator import (
    CertificateGenerationError,
    CertificateGenerator,
    GeneratedCertificate,
)
from identity.ca.crypto import (
    CryptoError,
    compute_thumbprint,
    decrypt_private_key,
    encrypt_private_key,
    generate_fernet_key,
    get_encryption_key,
)
from identity.ca.key_manager import KeyManager, KeyManagerError


class TestCryptoUtilities:
    """Tests for crypto.py utilities."""

    def test_generate_fernet_key_returns_valid_key(self):
        """Test generating a valid Fernet key."""
        key = generate_fernet_key()
        assert isinstance(key, str)
        # Fernet keys are 44 characters base64
        assert len(key) == 44

    def test_get_encryption_key_from_env(self, monkeypatch):
        """Test loading encryption key from environment."""
        test_key = generate_fernet_key()
        monkeypatch.setenv("CERT_ENCRYPTION_KEY", test_key)

        key = get_encryption_key()
        assert key is not None

    def test_get_encryption_key_missing_raises(self, monkeypatch):
        """Test that missing encryption key raises error."""
        monkeypatch.delenv("CERT_ENCRYPTION_KEY", raising=False)

        with pytest.raises(CryptoError, match="CERT_ENCRYPTION_KEY"):
            get_encryption_key()

    def test_encrypt_decrypt_private_key_roundtrip(self, monkeypatch):
        """Test encrypting and decrypting a private key."""
        test_key = generate_fernet_key()
        monkeypatch.setenv("CERT_ENCRYPTION_KEY", test_key)

        original_pem = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        encrypted = encrypt_private_key(original_pem)
        decrypted = decrypt_private_key(encrypted)

        assert decrypted == original_pem
        assert encrypted != original_pem

    def test_compute_thumbprint_returns_sha256(self):
        """Test computing SHA-256 thumbprint of a certificate."""
        # Create a minimal self-signed certificate for testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        thumbprint = compute_thumbprint(cert_pem)

        # SHA-256 thumbprint as hex is 64 characters
        assert len(thumbprint) == 64
        assert all(c in "0123456789abcdef" for c in thumbprint)


class TestKeyManager:
    """Tests for KeyManager CA key loading and generation."""

    def test_key_pair_raises_if_not_loaded(self):
        """Test that accessing key_pair before loading raises error."""
        manager = KeyManager()
        with pytest.raises(KeyManagerError, match="not loaded"):
            _ = manager.key_pair

    def test_load_or_generate_creates_rsa_key(self, monkeypatch):
        """Test that load_or_generate creates an RSA key when none exists."""
        # Clear environment to force generation
        monkeypatch.delenv("CA_KEY_PATH", raising=False)
        monkeypatch.delenv("CA_CERT_PATH", raising=False)
        monkeypatch.delenv("CA_KEY_PEM", raising=False)
        monkeypatch.delenv("CA_CERT_PEM", raising=False)
        monkeypatch.setenv("CA_ALGORITHM", "RSA")

        with patch("identity.ca.key_manager.identity_metrics"):
            manager = KeyManager()
            key_pair = manager.load_or_generate()

        assert isinstance(key_pair.private_key, rsa.RSAPrivateKey)
        assert key_pair.storage_type == "generated"
        assert key_pair.certificate is not None

    def test_load_or_generate_creates_ecdsa_key(self, monkeypatch):
        """Test that load_or_generate creates an ECDSA key when configured."""
        # Clear environment to force generation
        monkeypatch.delenv("CA_KEY_PATH", raising=False)
        monkeypatch.delenv("CA_CERT_PATH", raising=False)
        monkeypatch.delenv("CA_KEY_PEM", raising=False)
        monkeypatch.delenv("CA_CERT_PEM", raising=False)
        monkeypatch.setenv("CA_ALGORITHM", "ECDSA")

        with patch("identity.ca.key_manager.identity_metrics"):
            manager = KeyManager()
            key_pair = manager.load_or_generate()

        assert isinstance(key_pair.private_key, ec.EllipticCurvePrivateKey)
        assert key_pair.storage_type == "generated"

    def test_ca_certificate_has_correct_extensions(self, monkeypatch):
        """Test that generated CA certificate has correct extensions."""
        monkeypatch.delenv("CA_KEY_PATH", raising=False)
        monkeypatch.delenv("CA_CERT_PATH", raising=False)
        monkeypatch.delenv("CA_KEY_PEM", raising=False)
        monkeypatch.delenv("CA_CERT_PEM", raising=False)

        with patch("identity.ca.key_manager.identity_metrics"):
            manager = KeyManager()
            key_pair = manager.load_or_generate()

        # Check BasicConstraints - CA=True
        bc = key_pair.certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True

        # Check KeyUsage
        ku = key_pair.certificate.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True
        assert ku.critical is True


class TestCertificateGenerator:
    """Tests for CertificateGenerator."""

    @pytest.fixture
    def ca_key_pair(self, monkeypatch):
        """Create a CA key pair for testing."""
        monkeypatch.delenv("CA_KEY_PATH", raising=False)
        monkeypatch.delenv("CA_CERT_PATH", raising=False)
        monkeypatch.delenv("CA_KEY_PEM", raising=False)
        monkeypatch.delenv("CA_CERT_PEM", raising=False)

        with patch("identity.ca.key_manager.identity_metrics"):
            manager = KeyManager()
            return manager.load_or_generate()

    def test_generate_certificate_success(self, ca_key_pair):
        """Test generating a valid client certificate."""
        with patch("identity.ca.certificate_generator.identity_metrics"):
            generator = CertificateGenerator(ca_key_pair)
            subject_id = str(uuid4())

            result = generator.generate(subject_id)

        assert isinstance(result, GeneratedCertificate)
        assert result.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert result.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
        assert len(result.serial_number) == 16
        assert len(result.thumbprint) == 64
        assert result.not_before <= datetime.now(timezone.utc)
        assert result.not_after > datetime.now(timezone.utc)

    def test_generate_certificate_has_correct_subject(self, ca_key_pair):
        """Test that certificate has Subject CN=subject_id."""
        with patch("identity.ca.certificate_generator.identity_metrics"):
            generator = CertificateGenerator(ca_key_pair)
            subject_id = str(uuid4())

            result = generator.generate(subject_id)

        cert = x509.load_pem_x509_certificate(result.certificate_pem.encode())
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == subject_id

    def test_generate_certificate_has_client_auth_eku(self, ca_key_pair):
        """Test that certificate has Client Authentication EKU."""
        with patch("identity.ca.certificate_generator.identity_metrics"):
            generator = CertificateGenerator(ca_key_pair)

            result = generator.generate(str(uuid4()))

        cert = x509.load_pem_x509_certificate(result.certificate_pem.encode())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_inv11_max_validity_365_days(self, ca_key_pair):
        """Test INV-11: Certificate validity cannot exceed 365 days."""
        with patch("identity.ca.certificate_generator.identity_metrics"):
            generator = CertificateGenerator(ca_key_pair)

            with pytest.raises(CertificateGenerationError, match="INV-11"):
                generator.generate(str(uuid4()), validity_days=366)

    def test_generate_certificate_respects_validity_days(self, ca_key_pair):
        """Test that validity_days parameter is respected."""
        with patch("identity.ca.certificate_generator.identity_metrics"):
            generator = CertificateGenerator(ca_key_pair)

            result = generator.generate(str(uuid4()), validity_days=30)

        cert = x509.load_pem_x509_certificate(result.certificate_pem.encode())
        validity_delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        # Allow 1 day tolerance for timing
        assert 29 <= validity_delta.days <= 31

    def test_certificate_signed_by_ca(self, ca_key_pair):
        """Test that certificate is signed by the CA."""
        with patch("identity.ca.certificate_generator.identity_metrics"):
            generator = CertificateGenerator(ca_key_pair)

            result = generator.generate(str(uuid4()))

        cert = x509.load_pem_x509_certificate(result.certificate_pem.encode())

        # Issuer should match CA subject
        assert cert.issuer == ca_key_pair.certificate.subject
