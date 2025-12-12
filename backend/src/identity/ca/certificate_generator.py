"""X.509 certificate generation for client certificates.

Generates client certificates signed by the CA for machine clients.
"""

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from opentelemetry import trace

from identity.ca.crypto import compute_thumbprint
from identity.ca.key_manager import CAKeyPair
from identity.metrics import identity_metrics

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class CertificateGenerationError(Exception):
    """Raised when certificate generation fails."""

    pass


@dataclass
class GeneratedCertificate:
    """Result of certificate generation."""

    certificate_pem: str
    private_key_pem: str
    serial_number: str
    thumbprint: str
    not_before: datetime
    not_after: datetime


class CertificateGenerator:
    """Generates X.509 client certificates signed by the CA.

    Certificate attributes (per requirements):
    - Subject: CN=<subject_id>
    - Validity: now() to now() + validity_days (max 365 days, INV-11)
    - Key Usage: Digital Signature, Key Encipherment
    - Extended Key Usage: Client Authentication
    - Key: RSA 2048
    """

    # Configuration
    MAX_VALIDITY_DAYS = 365  # INV-11
    DEFAULT_VALIDITY_DAYS = 365
    CLIENT_KEY_SIZE = 2048

    def __init__(self, ca_key_pair: CAKeyPair) -> None:
        """Initialize generator with CA key pair.

        Args:
            ca_key_pair: The CA's private key and certificate for signing.
        """
        self._ca = ca_key_pair

    def generate(
        self,
        subject_id: str,
        validity_days: int | None = None,
    ) -> GeneratedCertificate:
        """Generate a new client certificate.

        Args:
            subject_id: UUID of the machine client (used as CN).
            validity_days: Certificate validity in days (max 365, default 365).

        Returns:
            GeneratedCertificate with all certificate details.

        Raises:
            CertificateGenerationError: If generation fails.
        """
        with tracer.start_as_current_span("CertificateGenerator.generate") as span:
            span.set_attribute("subject_id", subject_id)

            start_time = time.time()

            # Enforce INV-11: max 365 days validity
            if validity_days is None:
                validity_days = self.DEFAULT_VALIDITY_DAYS
            if validity_days > self.MAX_VALIDITY_DAYS:
                raise CertificateGenerationError(
                    f"Certificate validity cannot exceed {self.MAX_VALIDITY_DAYS} days (INV-11)"
                )

            span.set_attribute("validity_days", validity_days)

            try:
                # Generate client private key (RSA 2048)
                client_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=self.CLIENT_KEY_SIZE,
                )

                # Generate unique serial number from UUID
                serial_number = uuid.uuid4().int >> 64  # Use upper 64 bits of UUID
                serial_str = format(serial_number, "016x")

                span.set_attribute("serial", serial_str)

                # Certificate validity period
                now = datetime.now(timezone.utc)
                not_before = now
                not_after = now + timedelta(days=validity_days)

                # Build certificate
                subject = x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, subject_id),
                    ]
                )

                cert_builder = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(self._ca.certificate.subject)
                    .public_key(client_key.public_key())
                    .serial_number(serial_number)
                    .not_valid_before(not_before)
                    .not_valid_after(not_after)
                    .add_extension(
                        x509.BasicConstraints(ca=False, path_length=None),
                        critical=True,
                    )
                    .add_extension(
                        x509.KeyUsage(
                            digital_signature=True,
                            key_encipherment=True,
                            key_cert_sign=False,
                            crl_sign=False,
                            content_commitment=False,
                            data_encipherment=False,
                            key_agreement=False,
                            encipher_only=False,
                            decipher_only=False,
                        ),
                        critical=True,
                    )
                    .add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                        critical=False,
                    )
                )

                # Sign with CA key
                certificate = cert_builder.sign(
                    self._ca.private_key,
                    hashes.SHA256(),  # type: ignore[arg-type]
                )

                # Serialize to PEM
                cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                key_pem = client_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8")

                # Compute thumbprint
                thumbprint = compute_thumbprint(cert_pem)

                # Record metrics
                generation_time = time.time() - start_time
                identity_metrics.record_certificate_generated(generation_time)

                logger.info(
                    "certificate_generated",
                    extra={
                        "subject_id": subject_id,
                        "serial": serial_str,
                        "not_after": not_after.isoformat(),
                        "duration_seconds": generation_time,
                    },
                )

                return GeneratedCertificate(
                    certificate_pem=cert_pem,
                    private_key_pem=key_pem,
                    serial_number=serial_str,
                    thumbprint=thumbprint,
                    not_before=not_before,
                    not_after=not_after,
                )

            except CertificateGenerationError:
                raise
            except Exception as e:
                logger.error(
                    "certificate_generation_failed",
                    extra={"subject_id": subject_id, "error": str(e)},
                )
                raise CertificateGenerationError(f"Failed to generate certificate: {e}") from e
