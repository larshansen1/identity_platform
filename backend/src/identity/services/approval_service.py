"""Approval service for certificate request approval workflow."""

import logging
from uuid import UUID

from opentelemetry import trace
from sqlalchemy.ext.asyncio import AsyncSession

from identity.ca.key_manager import KeyManager
from identity.domain.models import (
    AdminUser,
    CertificateRequest,
    IdentityAuditLog,
    MachineClient,
)
from identity.domain.states import CertificateRequestStatus
from identity.metrics import identity_metrics
from identity.repository.repositories import (
    AuditLogRepository,
    CertificateRequestRepository,
    MachineClientRepository,
)
from identity.services.certificate_service import CertificateService
from identity.services.client_service import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RequestContext,
)

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class SelfApprovalError(ForbiddenError):
    """Raised when approver tries to approve their own client's request (INV-06)."""

    pass


class ApprovalService:
    """Service for certificate request approval workflow."""

    def __init__(self, db: AsyncSession, key_manager: KeyManager):
        self.db = db
        self.key_manager = key_manager
        self.request_repo = CertificateRequestRepository(db)
        self.client_repo = MachineClientRepository(db)
        self.audit_repo = AuditLogRepository(db)
        self._cert_service: CertificateService | None = None

    @property
    def cert_service(self) -> CertificateService:
        """Get certificate service (lazy initialization)."""
        if self._cert_service is None:
            self._cert_service = CertificateService(self.db, self.key_manager)
        return self._cert_service

    async def list_pending(
        self, limit: int = 20, offset: int = 0
    ) -> tuple[list[dict[str, str]], int]:
        """List pending certificate requests for approvers.

        Args:
            limit: Maximum number of results.
            offset: Pagination offset.

        Returns:
            Tuple of (list of request dicts with client/owner info, total count).
        """
        with tracer.start_as_current_span("ApprovalService.list_pending") as span:
            span.set_attribute("limit", limit)
            span.set_attribute("offset", offset)

            requests, total = await self.request_repo.list_pending(limit=limit, offset=offset)

            span.set_attribute("count", len(requests))
            span.set_attribute("total", total)

            # Transform to response format with client/owner info
            result = []
            for req in requests:
                client: MachineClient = req.client
                owner: AdminUser = client.owner
                result.append(
                    {
                        "request_id": str(req.request_id),
                        "subject_id": str(req.client_id),
                        "client_display_name": client.display_name,
                        "owner_email": owner.email,
                        "request_type": req.request_type,
                        "created_at": req.created_at.isoformat(),
                    }
                )

            return result, total

    async def approve(
        self,
        approver: AdminUser,
        request_id: UUID,
        request_context: RequestContext,
    ) -> CertificateRequest:
        """Approve a pending certificate request.

        Args:
            approver: The admin user approving the request.
            request_id: ID of the certificate request.
            request_context: HTTP request context for audit.

        Returns:
            Updated CertificateRequest with ISSUED status.

        Raises:
            NotFoundError: If request not found.
            ConflictError: If request is not in PENDING status.
            SelfApprovalError: If approver is the client owner (INV-06).
        """
        with tracer.start_as_current_span("ApprovalService.approve") as span:
            span.set_attribute("request_id", str(request_id))
            span.set_attribute("approver_id", str(approver.user_id))

            # Get request with client and owner info
            request = await self.request_repo.get_by_id(request_id)
            if not request:
                raise NotFoundError(f"Certificate request {request_id} not found")

            # Validate status
            if request.status != CertificateRequestStatus.PENDING.value:
                raise ConflictError(f"Request is not pending, current status: {request.status}")

            # Get client to check ownership
            client = await self.client_repo.get_by_id_any_owner(request.client_id)
            if not client:
                raise NotFoundError(f"Machine client {request.client_id} not found")

            span.set_attribute("subject_id", str(client.subject_id))

            # INV-06: Approver cannot approve requests for clients they own
            if client.owner_id == approver.user_id:
                raise SelfApprovalError(
                    "Cannot approve certificate request for your own client (INV-06)"
                )

            # Generate certificate (this updates the request with cert data)
            await self.cert_service.generate_certificate(request, client)

            # Transition to ISSUED via state machine
            request.approve(
                approver_id=approver.user_id,
                cert_pem=request.certificate_pem or "",
                key_pem=request.private_key_pem_encrypted or "",
            )
            await self.request_repo.update(request)

            # Write audit log
            audit_event = IdentityAuditLog(
                event_type="certificate_request.approved",
                actor_type="admin_user",
                actor_id=approver.user_id,
                resource_type="certificate_request",
                resource_id=request.request_id,
                action="approve",
                details={
                    "subject_id": str(client.subject_id),
                    "request_type": request.request_type,
                },
                ip_address=request_context.ip_address,
                user_agent=request_context.user_agent,
            )
            await self.audit_repo.create(audit_event)

            # Commit transaction
            await self.db.commit()

            # Record metrics
            identity_metrics.record_certificate_request_approved()

            logger.info(
                "certificate_request_approved",
                extra={
                    "request_id": str(request.request_id),
                    "approver_id": str(approver.user_id),
                },
            )

            return request

    async def reject(
        self,
        approver: AdminUser,
        request_id: UUID,
        reason: str,
        request_context: RequestContext,
    ) -> CertificateRequest:
        """Reject a pending certificate request.

        Args:
            approver: The admin user rejecting the request.
            request_id: ID of the certificate request.
            reason: Mandatory rejection reason (INV-07).
            request_context: HTTP request context for audit.

        Returns:
            Updated CertificateRequest with CANCELLED status.

        Raises:
            NotFoundError: If request not found.
            ConflictError: If request is not in PENDING status.
            ValueError: If reason is empty (INV-07).
        """
        with tracer.start_as_current_span("ApprovalService.reject") as span:
            span.set_attribute("request_id", str(request_id))
            span.set_attribute("approver_id", str(approver.user_id))
            span.set_attribute("reason", reason)

            # Get request
            request = await self.request_repo.get_by_id(request_id)
            if not request:
                raise NotFoundError(f"Certificate request {request_id} not found")

            # Validate status
            if request.status != CertificateRequestStatus.PENDING.value:
                raise ConflictError(f"Request is not pending, current status: {request.status}")

            # Transition to CANCELLED via state machine (validates reason, INV-07)
            request.reject(approver_id=approver.user_id, reason=reason)
            await self.request_repo.update(request)

            # Write audit log
            audit_event = IdentityAuditLog(
                event_type="certificate_request.rejected",
                actor_type="admin_user",
                actor_id=approver.user_id,
                resource_type="certificate_request",
                resource_id=request.request_id,
                action="reject",
                details={
                    "subject_id": str(request.client_id),
                    "reason": reason,
                },
                ip_address=request_context.ip_address,
                user_agent=request_context.user_agent,
            )
            await self.audit_repo.create(audit_event)

            # Commit transaction
            await self.db.commit()

            # Record metrics
            identity_metrics.record_certificate_request_rejected()

            logger.info(
                "certificate_request_rejected",
                extra={
                    "request_id": str(request.request_id),
                    "approver_id": str(approver.user_id),
                    "reason": reason,
                },
            )

            return request
