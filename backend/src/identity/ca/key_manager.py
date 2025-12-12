"""CA key management for loading and generating CA keys and certificates.

Supports multiple storage backends:
- File-based (CA_KEY_PATH, CA_CERT_PATH)
- Environment variable (CA_KEY_PEM, CA_CERT_PEM as base64)

Generates new CA on first startup if no key is found.
"""

import base64
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID
from opentelemetry import trace

from identity.metrics import identity_metrics

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class KeyManagerError(Exception):
    """Raised when CA key management fails."""

    pass


@dataclass
class CAKeyPair:
    """Holds CA private key and certificate."""

    private_key: PrivateKeyTypes
    certificate: x509.Certificate
    storage_type: str  # "file", "env", or "generated"

    @property
    def certificate_pem(self) -> str:
        """Get CA certificate as PEM string."""
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class KeyManager:
    """Manages CA key loading and generation.

    Storage priority:
    1. File (CA_KEY_PATH, CA_CERT_PATH)
    2. Environment (CA_KEY_PEM, CA_CERT_PEM - base64 encoded)
    3. Generate new (writes to CA_KEY_PATH if writable)
    """

    # Configuration
    CA_KEY_PATH_ENV = "CA_KEY_PATH"
    CA_CERT_PATH_ENV = "CA_CERT_PATH"
    CA_KEY_PEM_ENV = "CA_KEY_PEM"
    CA_CERT_PEM_ENV = "CA_CERT_PEM"
    CA_ALGORITHM_ENV = "CA_ALGORITHM"  # "RSA" or "ECDSA"

    # Defaults
    DEFAULT_CA_VALIDITY_YEARS = 10
    DEFAULT_ALGORITHM = "RSA"
    RSA_KEY_SIZE = 4096
    ECDSA_CURVE = ec.SECP384R1()

    def __init__(self) -> None:
        self._key_pair: CAKeyPair | None = None

    @property
    def key_pair(self) -> CAKeyPair:
        """Get loaded CA key pair. Raises if not loaded."""
        if self._key_pair is None:
            raise KeyManagerError("CA key not loaded. Call load_or_generate() first.")
        return self._key_pair

    def load_or_generate(self) -> CAKeyPair:
        """Load CA key from configured source or generate new one.

        Returns:
            Loaded or generated CAKeyPair.

        Raises:
            KeyManagerError: If loading/generation fails.
        """
        with tracer.start_as_current_span("KeyManager.load_ca_key") as span:
            # Try loading from file
            key_pair = self._try_load_from_file()
            if key_pair:
                span.set_attribute("storage_type", "file")
                span.set_attribute("algorithm", self._get_algorithm_name(key_pair.private_key))
                span.set_attribute(
                    "ca_cert_expires", key_pair.certificate.not_valid_after_utc.isoformat()
                )
                self._key_pair = key_pair
                self._log_loaded(key_pair)
                return key_pair

            # Try loading from environment
            key_pair = self._try_load_from_env()
            if key_pair:
                span.set_attribute("storage_type", "env")
                span.set_attribute("algorithm", self._get_algorithm_name(key_pair.private_key))
                span.set_attribute(
                    "ca_cert_expires", key_pair.certificate.not_valid_after_utc.isoformat()
                )
                self._key_pair = key_pair
                self._log_loaded(key_pair)
                return key_pair

            # Generate new key pair
            key_pair = self._generate_new()
            span.set_attribute("storage_type", "generated")
            span.set_attribute("algorithm", self._get_algorithm_name(key_pair.private_key))
            span.set_attribute(
                "ca_cert_expires", key_pair.certificate.not_valid_after_utc.isoformat()
            )
            self._key_pair = key_pair
            self._log_loaded(key_pair)
            return key_pair

    def _try_load_from_file(self) -> CAKeyPair | None:
        """Try loading CA key from file paths."""
        key_path = os.environ.get(self.CA_KEY_PATH_ENV)
        cert_path = os.environ.get(self.CA_CERT_PATH_ENV)

        if not key_path or not cert_path:
            return None

        key_file = Path(key_path)
        cert_file = Path(cert_path)

        if not key_file.exists() or not cert_file.exists():
            logger.debug(
                "CA key/cert files not found",
                extra={"key_path": key_path, "cert_path": cert_path},
            )
            return None

        try:
            key_pem = key_file.read_bytes()
            cert_pem = cert_file.read_bytes()

            private_key = serialization.load_pem_private_key(key_pem, password=None)
            certificate = x509.load_pem_x509_certificate(cert_pem)

            return CAKeyPair(
                private_key=private_key,
                certificate=certificate,
                storage_type="file",
            )
        except Exception as e:
            logger.error(
                "ca_key_load_failed",
                extra={"storage_type": "file", "error": str(e)},
            )
            raise KeyManagerError(f"Failed to load CA from file: {e}") from e

    def _try_load_from_env(self) -> CAKeyPair | None:
        """Try loading CA key from environment variables (base64 encoded)."""
        key_b64 = os.environ.get(self.CA_KEY_PEM_ENV)
        cert_b64 = os.environ.get(self.CA_CERT_PEM_ENV)

        if not key_b64 or not cert_b64:
            return None

        try:
            key_pem = base64.b64decode(key_b64)
            cert_pem = base64.b64decode(cert_b64)

            private_key = serialization.load_pem_private_key(key_pem, password=None)
            certificate = x509.load_pem_x509_certificate(cert_pem)

            return CAKeyPair(
                private_key=private_key,
                certificate=certificate,
                storage_type="env",
            )
        except Exception as e:
            logger.error(
                "ca_key_load_failed",
                extra={"storage_type": "env", "error": str(e)},
            )
            raise KeyManagerError(f"Failed to load CA from environment: {e}") from e

    def _generate_new(self) -> CAKeyPair:
        """Generate a new CA key pair."""
        algorithm = os.environ.get(self.CA_ALGORITHM_ENV, self.DEFAULT_ALGORITHM).upper()

        logger.info("Generating new CA key pair", extra={"algorithm": algorithm})

        # Generate private key
        if algorithm == "ECDSA":
            private_key: PrivateKeyTypes = ec.generate_private_key(self.ECDSA_CURVE)
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.RSA_KEY_SIZE,
            )

        # Generate self-signed CA certificate
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Identity Platform CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Identity Platform"),
            ]
        )

        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())  # type: ignore[arg-type]
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365 * self.DEFAULT_CA_VALIDITY_YEARS))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
        )

        key_pair = CAKeyPair(
            private_key=private_key,
            certificate=certificate,
            storage_type="generated",
        )

        # Try to save to file if path is configured
        self._try_save_to_file(key_pair)

        return key_pair

    def _try_save_to_file(self, key_pair: CAKeyPair) -> None:
        """Try saving generated key pair to file."""
        key_path = os.environ.get(self.CA_KEY_PATH_ENV)
        cert_path = os.environ.get(self.CA_CERT_PATH_ENV)

        if not key_path or not cert_path:
            logger.warning(
                "CA key generated but not saved - set CA_KEY_PATH and CA_CERT_PATH to persist"
            )
            return

        try:
            key_pem = key_pair.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            cert_pem = key_pair.certificate.public_bytes(serialization.Encoding.PEM)

            Path(key_path).write_bytes(key_pem)
            Path(cert_path).write_bytes(cert_pem)

            logger.info(
                "CA key pair saved to file",
                extra={"key_path": key_path, "cert_path": cert_path},
            )
        except Exception as e:
            logger.warning(
                "Failed to save CA key pair to file",
                extra={"error": str(e)},
            )

    def _log_loaded(self, key_pair: CAKeyPair) -> None:
        """Log successful key loading and record metrics."""
        algorithm = self._get_algorithm_name(key_pair.private_key)
        expires = key_pair.certificate.not_valid_after_utc.isoformat()

        logger.info(
            "ca_key_loaded",
            extra={
                "storage_type": key_pair.storage_type,
                "algorithm": algorithm,
                "ca_cert_expires": expires,
            },
        )

        identity_metrics.record_ca_key_loaded(key_pair.storage_type)

    def _get_algorithm_name(self, key: PrivateKeyTypes) -> str:
        """Get algorithm name from private key."""
        if isinstance(key, rsa.RSAPrivateKey):
            return f"RSA-{key.key_size}"
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            return f"ECDSA-{key.curve.name}"
        return "UNKNOWN"
