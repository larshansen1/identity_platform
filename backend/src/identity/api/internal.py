"""Internal API for certificate validation.

This endpoint is called by the Authorization module to validate client certificates.
"""

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from opentelemetry import trace
from pydantic import BaseModel
from shared.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

from identity.domain.states import MachineClientStatus
from identity.metrics import identity_metrics
from identity.repository.repositories import IssuedCertificateRepository, MachineClientRepository

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)

router = APIRouter(prefix="/internal/identity", tags=["internal"])


# =============================================================================
# Request/Response Schemas
# =============================================================================


class ValidateCertificateRequest(BaseModel):
    """Request to validate a client certificate."""

    subject_id: UUID
    certificate_thumbprint: str


class ValidateCertificateResponse(BaseModel):
    """Response from certificate validation."""

    valid: bool
    subject_id: str | None = None
    subject_type: str | None = None
    status: str | None = None
    reason: str | None = None


# Validation failure reasons
class ValidationReason:
    """Constants for validation failure reasons."""

    UNKNOWN_SUBJECT = "UNKNOWN_SUBJECT"
    THUMBPRINT_MISMATCH = "THUMBPRINT_MISMATCH"
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    SUBJECT_REVOKED = "SUBJECT_REVOKED"
    CERTIFICATE_REVOKED = "CERTIFICATE_REVOKED"


# =============================================================================
# Endpoint
# =============================================================================


@router.post("/validate-certificate", response_model=ValidateCertificateResponse)
async def validate_certificate(
    body: ValidateCertificateRequest,
    db: AsyncSession = Depends(get_db),
) -> ValidateCertificateResponse:
    """Validate a client certificate.

    Called by Authorization module during token issuance.
    Validates:
    1. Subject exists
    2. Thumbprint matches
    3. Subject is ACTIVE
    4. Certificate is not expired
    5. Certificate is not revoked (INV-16)

    Returns:
        valid=true with subject info, or valid=false with reason.
    """
    with tracer.start_as_current_span("validate_certificate") as span:
        span.set_attribute("subject_id", str(body.subject_id))

        client_repo = MachineClientRepository(db)
        cert_repo = IssuedCertificateRepository(db)

        # 1. Check if subject exists
        client = await client_repo.get_by_id_any_owner(body.subject_id)
        if client is None:
            span.set_attribute("result", "invalid")
            span.set_attribute("reason", ValidationReason.UNKNOWN_SUBJECT)
            identity_metrics.record_certificate_validation("invalid")
            logger.debug(
                "certificate_validated",
                extra={"subject_id": str(body.subject_id), "result": "invalid"},
            )
            return ValidateCertificateResponse(
                valid=False,
                reason=ValidationReason.UNKNOWN_SUBJECT,
            )

        # 2. Check thumbprint matches
        if client.certificate_thumbprint != body.certificate_thumbprint:
            span.set_attribute("result", "invalid")
            span.set_attribute("reason", ValidationReason.THUMBPRINT_MISMATCH)
            identity_metrics.record_certificate_validation("invalid")
            logger.debug(
                "certificate_validated",
                extra={"subject_id": str(body.subject_id), "result": "invalid"},
            )
            return ValidateCertificateResponse(
                valid=False,
                reason=ValidationReason.THUMBPRINT_MISMATCH,
            )

        # 3. Check subject is ACTIVE
        if client.status != MachineClientStatus.ACTIVE.value:
            span.set_attribute("result", "invalid")
            span.set_attribute("reason", ValidationReason.SUBJECT_REVOKED)
            identity_metrics.record_certificate_validation("invalid")
            logger.debug(
                "certificate_validated",
                extra={"subject_id": str(body.subject_id), "result": "invalid"},
            )
            return ValidateCertificateResponse(
                valid=False,
                reason=ValidationReason.SUBJECT_REVOKED,
            )

        # 4. Check certificate expiry (runtime check)
        now = datetime.now(timezone.utc)
        if client.certificate_not_after and client.certificate_not_after < now:
            span.set_attribute("result", "invalid")
            span.set_attribute("reason", ValidationReason.CERTIFICATE_EXPIRED)
            identity_metrics.record_certificate_validation("invalid")
            logger.debug(
                "certificate_validated",
                extra={"subject_id": str(body.subject_id), "result": "invalid"},
            )
            return ValidateCertificateResponse(
                valid=False,
                reason=ValidationReason.CERTIFICATE_EXPIRED,
            )

        # 5. Check certificate revocation (INV-16)
        if client.certificate_serial:
            identity_metrics.record_revocation_check("checking")
            issued_cert = await cert_repo.get_by_serial(client.certificate_serial)
            if issued_cert and issued_cert.revoked_at is not None:
                span.set_attribute("result", "invalid")
                span.set_attribute("reason", ValidationReason.CERTIFICATE_REVOKED)
                identity_metrics.record_certificate_validation("invalid")
                identity_metrics.record_revocation_check("revoked")
                logger.debug(
                    "certificate_validated",
                    extra={"subject_id": str(body.subject_id), "result": "invalid"},
                )
                return ValidateCertificateResponse(
                    valid=False,
                    reason=ValidationReason.CERTIFICATE_REVOKED,
                )
            identity_metrics.record_revocation_check("valid")

        # All checks passed
        span.set_attribute("result", "valid")
        identity_metrics.record_certificate_validation("valid")
        logger.debug(
            "certificate_validated",
            extra={"subject_id": str(body.subject_id), "result": "valid"},
        )

        return ValidateCertificateResponse(
            valid=True,
            subject_id=str(client.subject_id),
            subject_type=client.subject_type,
            status=client.status,
        )
