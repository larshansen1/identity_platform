"""Certificate service for certificate generation and download operations."""

import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

from opentelemetry import trace
from sqlalchemy.ext.asyncio import AsyncSession

from identity.ca.certificate_generator import CertificateGenerator, GeneratedCertificate
from identity.ca.crypto import decrypt_private_key, encrypt_private_key
from identity.ca.key_manager import KeyManager
from identity.domain.models import (
    CertificateRequest,
    IdentityAuditLog,
    IssuedCertificate,
    MachineClient,
)
from identity.metrics import identity_metrics
from identity.repository.repositories import (
    AuditLogRepository,
    CertificateRequestRepository,
    IssuedCertificateRepository,
    MachineClientRepository,
)
from identity.services.client_service import ConflictError, NotFoundError, RequestContext

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class DownloadExpiredError(Exception):
    """Raised when certificate download window has expired."""

    pass


class CertificateService:
    """Service for certificate generation and download operations."""

    # Download window duration after approval
    DOWNLOAD_WINDOW_HOURS = 24

    def __init__(self, db: AsyncSession, key_manager: KeyManager):
        self.db = db
        self.key_manager = key_manager
        self.request_repo = CertificateRequestRepository(db)
        self.issued_cert_repo = IssuedCertificateRepository(db)
        self.client_repo = MachineClientRepository(db)
        self.audit_repo = AuditLogRepository(db)
        self._generator: CertificateGenerator | None = None

    @property
    def generator(self) -> CertificateGenerator:
        """Get certificate generator (lazy initialization)."""
        if self._generator is None:
            self._generator = CertificateGenerator(self.key_manager.key_pair)
        return self._generator

    async def generate_certificate(
        self,
        request: CertificateRequest,
        client: MachineClient,
    ) -> tuple[str, str, IssuedCertificate]:
        """Generate a certificate for an approved request.

        Args:
            request: The approved certificate request.
            client: The machine client for the certificate.

        Returns:
            Tuple of (cert_pem, encrypted_key_pem, issued_cert).
        """
        with tracer.start_as_current_span("CertificateService.generate_certificate") as span:
            span.set_attribute("request_id", str(request.request_id))
            span.set_attribute("subject_id", str(client.subject_id))

            # Generate the certificate
            generated: GeneratedCertificate = self.generator.generate(
                subject_id=str(client.subject_id),
            )

            span.set_attribute("serial", generated.serial_number)
            span.set_attribute("not_after", generated.not_after.isoformat())

            # Encrypt the private key
            encrypted_key = encrypt_private_key(generated.private_key_pem)

            # Create IssuedCertificate record
            issued_cert = IssuedCertificate(
                client_id=client.subject_id,
                serial_number=generated.serial_number,
                thumbprint=generated.thumbprint,
                not_before=generated.not_before,
                not_after=generated.not_after,
            )
            await self.issued_cert_repo.create(issued_cert)

            # Update request with certificate data and download window
            request.certificate_pem = generated.certificate_pem
            request.private_key_pem_encrypted = encrypted_key
            request.download_expires_at = datetime.now(timezone.utc) + timedelta(
                hours=self.DOWNLOAD_WINDOW_HOURS
            )
            await self.request_repo.update(request)

            logger.info(
                "certificate_generated",
                extra={
                    "request_id": str(request.request_id),
                    "subject_id": str(client.subject_id),
                    "serial": generated.serial_number,
                    "not_after": generated.not_after.isoformat(),
                },
            )

            return generated.certificate_pem, encrypted_key, issued_cert

    async def download_certificate(
        self,
        request: CertificateRequest,
        client: MachineClient,
        request_context: RequestContext,
    ) -> dict[str, str]:
        """Download certificate bundle and activate client.

        Args:
            request: The issued certificate request.
            client: The machine client.
            request_context: HTTP request context for audit.

        Returns:
            Dictionary with certificate_pem, private_key_pem, ca_certificate_pem, subject_id.

        Raises:
            ConflictError: If request is not in ISSUED status.
            DownloadExpiredError: If download window has expired.
        """
        with tracer.start_as_current_span("CertificateService.download_certificate") as span:
            span.set_attribute("request_id", str(request.request_id))
            span.set_attribute("subject_id", str(client.subject_id))

            from identity.domain.states import CertificateRequestStatus

            # Validate status
            if request.status != CertificateRequestStatus.ISSUED.value:
                raise ConflictError(f"Request is not issued, current status: {request.status}")

            # Validate download window
            if request.download_expires_at and request.download_expires_at < datetime.now(
                timezone.utc
            ):
                raise DownloadExpiredError("Certificate download window has expired")

            # Decrypt private key
            if not request.private_key_pem_encrypted:
                raise ConflictError("No private key available for download")

            private_key_pem = decrypt_private_key(request.private_key_pem_encrypted)

            # Parse certificate to get details for client update
            from identity.ca.crypto import compute_thumbprint

            cert_pem = request.certificate_pem
            if not cert_pem:
                raise ConflictError("No certificate available for download")

            thumbprint = compute_thumbprint(cert_pem)

            # Get certificate details from IssuedCertificate record
            from cryptography import x509

            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            serial = format(cert.serial_number, "016x")[:16]  # Match our serial format

            # Update client with certificate info and activate
            client.install_certificate(
                thumbprint=thumbprint,
                serial=serial,
                not_before=cert.not_valid_before_utc,
                not_after=cert.not_valid_after_utc,
            )
            await self.client_repo.update(client)

            # Complete the download (transition request to COMPLETED)
            request.complete_download()
            await self.request_repo.update(request)

            # Write audit log
            audit_event = IdentityAuditLog(
                event_type="certificate.downloaded",
                actor_type="admin_user",
                actor_id=request.requester_id,
                resource_type="certificate_request",
                resource_id=request.request_id,
                action="download",
                details={"subject_id": str(client.subject_id)},
                ip_address=request_context.ip_address,
                user_agent=request_context.user_agent,
            )
            await self.audit_repo.create(audit_event)

            # Commit transaction
            await self.db.commit()

            # Record metrics
            identity_metrics.record_certificate_downloaded()

            logger.info(
                "certificate_downloaded",
                extra={
                    "request_id": str(request.request_id),
                    "subject_id": str(client.subject_id),
                },
            )

            return {
                "certificate_pem": cert_pem,
                "private_key_pem": private_key_pem,
                "ca_certificate_pem": self.key_manager.key_pair.certificate_pem,
                "subject_id": str(client.subject_id),
            }

    async def get_request_for_download(
        self,
        request_id: UUID,
        client_id: UUID,
        owner_id: UUID,
    ) -> tuple[CertificateRequest, MachineClient]:
        """Get request and client for download, validating ownership.

        Args:
            request_id: The certificate request ID.
            client_id: The client ID from the URL.
            owner_id: The owner's user ID.

        Returns:
            Tuple of (request, client).

        Raises:
            NotFoundError: If request or client not found or not owned.
        """
        request = await self.request_repo.get_by_id_for_client_owner(
            request_id=request_id,
            client_id=client_id,
            owner_id=owner_id,
        )
        if not request:
            raise NotFoundError("Certificate request not found")

        client = await self.client_repo.get_by_id(
            subject_id=client_id,
            owner_id=owner_id,
        )
        if not client:
            raise NotFoundError("Machine client not found")

        return request, client
