"""Client service for machine client lifecycle management."""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from opentelemetry import trace
from sqlalchemy.ext.asyncio import AsyncSession

from identity.domain.models import (
    AdminUser,
    CertificateRequest,
    IdentityAuditLog,
    MachineClient,
)
from identity.domain.states import (
    AdminRole,
    CertificateRequestStatus,
    CertificateRequestType,
    MachineClientStatus,
    SubjectType,
)
from identity.metrics import identity_metrics
from identity.repository.repositories import (
    AuditLogRepository,
    CertificateRequestRepository,
    IssuedCertificateRepository,
    MachineClientRepository,
)

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)


class NotFoundError(Exception):
    """Raised when a resource is not found."""

    pass


class ForbiddenError(Exception):
    """Raised when an operation is not permitted."""

    pass


class ConflictError(Exception):
    """Raised when there is a state conflict."""

    pass


@dataclass
class RequestContext:
    """Context from the incoming HTTP request for audit logging."""

    ip_address: str | None = None
    user_agent: str | None = None


class ClientService:
    """Service for machine client lifecycle management."""

    # Certificate request expiry
    REQUEST_EXPIRY_DAYS = 7

    def __init__(self, db: AsyncSession):
        self.db = db
        self.client_repo = MachineClientRepository(db)
        self.audit_repo = AuditLogRepository(db)
        self.request_repo = CertificateRequestRepository(db)
        self.issued_cert_repo = IssuedCertificateRepository(db)

    async def create_machine_client(
        self,
        owner: AdminUser,
        display_name: str,
        description: str | None,
        request_context: RequestContext,
    ) -> MachineClient:
        """
        Create a new machine client.

        - Validates: owner has REQUESTER role
        - Creates: MachineClient in PENDING_CERTIFICATE state
        - Audit: machine_client.created event
        - Log: INFO subject_created {subject_id, type, owner_id}
        - Metric: identity_subjects_created_total{type="machine_client"} +1
        """
        with tracer.start_as_current_span("ClientService.create_machine_client") as span:
            span.set_attribute("owner_id", str(owner.user_id))
            span.set_attribute("display_name", display_name)

            # Validate role
            if not owner.has_role(AdminRole.REQUESTER):
                raise ForbiddenError("Requires REQUESTER role")

            # Create client with PENDING_CERTIFICATE status
            client = MachineClient(
                owner_id=owner.user_id,
                display_name=display_name,
                description=description,
                status=MachineClientStatus.PENDING_CERTIFICATE.value,
                subject_type=SubjectType.MACHINE_CLIENT.value,
            )

            client = await self.client_repo.create(client)

            # Write audit log
            audit_event = IdentityAuditLog(
                event_type="machine_client.created",
                actor_type="admin_user",
                actor_id=owner.user_id,
                resource_type="machine_client",
                resource_id=client.subject_id,
                action="create",
                details={"display_name": display_name},
                ip_address=request_context.ip_address,
                user_agent=request_context.user_agent,
            )
            await self.audit_repo.create(audit_event)

            # Commit the transaction
            await self.db.commit()

            # Emit metric
            identity_metrics.record_subject_created(SubjectType.MACHINE_CLIENT.value)

            # Structured log
            logger.info(
                "subject_created",
                extra={
                    "subject_id": str(client.subject_id),
                    "type": SubjectType.MACHINE_CLIENT.value,
                    "owner_id": str(owner.user_id),
                },
            )

            span.set_attribute("subject_id", str(client.subject_id))
            return client

    async def list_machine_clients(
        self,
        owner: AdminUser,
        status: MachineClientStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[MachineClient], int]:
        """
        List clients owned by this admin (INV-13).

        - Log: DEBUG subjects_listed {owner_id, type, count}
        """
        with tracer.start_as_current_span("ClientService.list_machine_clients") as span:
            span.set_attribute("owner_id", str(owner.user_id))
            span.set_attribute("limit", limit)
            span.set_attribute("offset", offset)

            clients, total = await self.client_repo.list_by_owner(
                owner_id=owner.user_id,
                status=status,
                limit=limit,
                offset=offset,
            )

            logger.debug(
                "subjects_listed",
                extra={
                    "owner_id": str(owner.user_id),
                    "type": SubjectType.MACHINE_CLIENT.value,
                    "count": len(clients),
                    "total": total,
                },
            )

            span.set_attribute("count", len(clients))
            span.set_attribute("total", total)
            return clients, total

    async def get_machine_client(
        self,
        owner: AdminUser,
        subject_id: UUID,
    ) -> MachineClient:
        """
        Get client if owned by this admin (INV-13).

        Raises: NotFoundError if not found or not owned
        """
        with tracer.start_as_current_span("ClientService.get_machine_client") as span:
            span.set_attribute("owner_id", str(owner.user_id))
            span.set_attribute("subject_id", str(subject_id))

            client = await self.client_repo.get_by_id(
                subject_id=subject_id,
                owner_id=owner.user_id,
            )

            if client is None:
                raise NotFoundError(f"Machine client {subject_id} not found")

            return client

    async def create_certificate_request(
        self,
        owner: AdminUser,
        subject_id: UUID,
        request_context: RequestContext,
    ) -> CertificateRequest:
        """
        Create a certificate request for a machine client.

        - Validates: owner has REQUESTER role
        - Validates: client.status != REVOKED
        - Validates: no pending request exists (INV-05)
        - Determines request_type: INITIAL or RENEWAL
        - Audit: certificate_request.created event
        - Log: INFO certificate_request_created
        - Metric: identity_certificate_requests_created_total{type}
        """
        with tracer.start_as_current_span("ClientService.create_certificate_request") as span:
            span.set_attribute("owner_id", str(owner.user_id))
            span.set_attribute("subject_id", str(subject_id))

            # Validate role
            if not owner.has_role(AdminRole.REQUESTER):
                raise ForbiddenError("Requires REQUESTER role")

            # Get client (enforces ownership via INV-13)
            client = await self.client_repo.get_by_id(
                subject_id=subject_id,
                owner_id=owner.user_id,
            )

            if client is None:
                raise NotFoundError(f"Machine client {subject_id} not found")

            # Validate client is not revoked
            if client.status == MachineClientStatus.REVOKED.value:
                raise ConflictError("Cannot create certificate request for revoked client")

            # Check for existing pending request (INV-05)
            has_pending = await self.request_repo.has_pending_request(subject_id)
            if has_pending:
                raise ConflictError(
                    "A pending certificate request already exists for this client (INV-05)"
                )

            # Determine request type
            if client.certificate_thumbprint is None:
                request_type = CertificateRequestType.INITIAL.value
            else:
                request_type = CertificateRequestType.RENEWAL.value

            span.set_attribute("request_type", request_type)

            # Create the request
            now = datetime.now(timezone.utc)
            request = CertificateRequest(
                client_id=subject_id,
                requester_id=owner.user_id,
                request_type=request_type,
                status=CertificateRequestStatus.PENDING.value,
                expires_at=now + timedelta(days=self.REQUEST_EXPIRY_DAYS),
            )

            request = await self.request_repo.create(request)

            span.set_attribute("request_id", str(request.request_id))

            # Write audit log
            audit_event = IdentityAuditLog(
                event_type="certificate_request.created",
                actor_type="admin_user",
                actor_id=owner.user_id,
                resource_type="certificate_request",
                resource_id=request.request_id,
                action="create",
                details={
                    "subject_id": str(subject_id),
                    "request_type": request_type,
                },
                ip_address=request_context.ip_address,
                user_agent=request_context.user_agent,
            )
            await self.audit_repo.create(audit_event)

            # Commit transaction
            await self.db.commit()

            # Record metrics
            identity_metrics.record_certificate_request_created(request_type)

            # Structured log
            logger.info(
                "certificate_request_created",
                extra={
                    "request_id": str(request.request_id),
                    "subject_id": str(subject_id),
                    "type": request_type,
                },
            )

            return request

    async def get_certificate_request(
        self,
        owner: AdminUser,
        client_id: UUID,
        request_id: UUID,
    ) -> CertificateRequest:
        """Get certificate request if client is owned by this admin."""
        with tracer.start_as_current_span("ClientService.get_certificate_request") as span:
            span.set_attribute("owner_id", str(owner.user_id))
            span.set_attribute("client_id", str(client_id))
            span.set_attribute("request_id", str(request_id))

            request = await self.request_repo.get_by_id_for_client_owner(
                request_id=request_id,
                client_id=client_id,
                owner_id=owner.user_id,
            )

            if request is None:
                raise NotFoundError(f"Certificate request {request_id} not found")

            return request

    async def delete_machine_client(
        self,
        owner: AdminUser,
        subject_id: UUID,
        request_context: RequestContext,
    ) -> None:
        """
        Delete (revoke) a machine client.

        - Validates: owner has REQUESTER role
        - Validates: client.status != REVOKED (INV-04)
        - Cancels: any PENDING certificate requests
        - Revokes: all issued certificates
        - Sets: status -> REVOKED
        - Audit: machine_client.revoked event
        - Log: INFO subject_revoked {subject_id, type}
        - Metric: identity_subjects_revoked_total{type="machine_client"} +1
        """
        with tracer.start_as_current_span("ClientService.delete_machine_client") as span:
            span.set_attribute("owner_id", str(owner.user_id))
            span.set_attribute("subject_id", str(subject_id))

            # Validate role
            if not owner.has_role(AdminRole.REQUESTER):
                raise ForbiddenError("Requires REQUESTER role")

            # Get client (enforces ownership via INV-13)
            client = await self.client_repo.get_by_id(
                subject_id=subject_id,
                owner_id=owner.user_id,
            )

            if client is None:
                raise NotFoundError(f"Machine client {subject_id} not found")

            # Check if already revoked (INV-04)
            if client.status == MachineClientStatus.REVOKED.value:
                raise ConflictError("Client is already revoked")

            # Cancel any pending certificate requests
            cancelled_count = await self.request_repo.cancel_pending_for_client(subject_id)
            if cancelled_count > 0:
                logger.info(
                    "pending_requests_cancelled",
                    extra={"subject_id": str(subject_id), "count": cancelled_count},
                )

            # Revoke all issued certificates
            revoked_count = await self.issued_cert_repo.revoke_all_for_client(
                subject_id, reason="client_deleted"
            )
            if revoked_count > 0:
                logger.info(
                    "certificates_revoked",
                    extra={"subject_id": str(subject_id), "count": revoked_count},
                )
                for _ in range(revoked_count):
                    identity_metrics.record_certificate_revoked("client_deleted")

            # Revoke the client
            client.revoke()
            await self.client_repo.update(client)

            # Write audit log
            audit_event = IdentityAuditLog(
                event_type="machine_client.revoked",
                actor_type="admin_user",
                actor_id=owner.user_id,
                resource_type="machine_client",
                resource_id=client.subject_id,
                action="revoke",
                details={
                    "previous_status": client.status,
                    "cancelled_requests": cancelled_count,
                    "revoked_certificates": revoked_count,
                },
                ip_address=request_context.ip_address,
                user_agent=request_context.user_agent,
            )
            await self.audit_repo.create(audit_event)

            # Commit the transaction
            await self.db.commit()

            # Emit metric
            identity_metrics.record_subject_revoked(SubjectType.MACHINE_CLIENT.value)

            # Structured log
            logger.info(
                "subject_revoked",
                extra={
                    "subject_id": str(subject_id),
                    "type": SubjectType.MACHINE_CLIENT.value,
                },
            )
