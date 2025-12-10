"""Client service for machine client lifecycle management."""

import logging
from dataclasses import dataclass
from uuid import UUID

from opentelemetry import trace
from sqlalchemy.ext.asyncio import AsyncSession

from identity.domain.models import (
    AdminUser,
    IdentityAuditLog,
    MachineClient,
)
from identity.domain.states import (
    AdminRole,
    MachineClientStatus,
    SubjectType,
)
from identity.metrics import identity_metrics
from identity.repository.repositories import (
    AuditLogRepository,
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

    def __init__(self, db: AsyncSession):
        self.db = db
        self.client_repo = MachineClientRepository(db)
        self.audit_repo = AuditLogRepository(db)

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
                details={"previous_status": client.status},
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
