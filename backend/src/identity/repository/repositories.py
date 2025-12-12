"""Repository layer for Identity module data access."""

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from identity.domain.models import (
    AdminUser,
    CertificateRequest,
    IdentityAuditLog,
    IssuedCertificate,
    MachineClient,
)
from identity.domain.states import AdminRole, CertificateRequestStatus, MachineClientStatus

logger = logging.getLogger(__name__)


class AdminUserRepository:
    """Repository for AdminUser CRUD operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, user_id: UUID) -> AdminUser | None:
        """Get admin user by ID."""
        result = await self.db.execute(select(AdminUser).where(AdminUser.user_id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> AdminUser | None:
        """Get admin user by email."""
        result = await self.db.execute(select(AdminUser).where(AdminUser.email == email))
        return result.scalar_one_or_none()

    async def get_by_api_key_hash(self, api_key_hash: str) -> AdminUser | None:
        """Get admin user by API key hash."""
        result = await self.db.execute(
            select(AdminUser).where(AdminUser.api_key_hash == api_key_hash)
        )
        return result.scalar_one_or_none()

    async def create(self, admin: AdminUser) -> AdminUser:
        """Create a new admin user."""
        self.db.add(admin)
        await self.db.flush()
        return admin

    async def count_by_role(self, role: AdminRole) -> int:
        """Count admin users with a specific role."""
        result = await self.db.execute(
            select(func.count())
            .select_from(AdminUser)
            .where(AdminUser.roles.contains([role.value]))
        )
        return result.scalar_one()

    async def count_all(self) -> int:
        """Count all admin users."""
        result = await self.db.execute(select(func.count()).select_from(AdminUser))
        return result.scalar_one()


class MachineClientRepository:
    """Repository for MachineClient CRUD with owner-based filtering (INV-13)."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, subject_id: UUID, owner_id: UUID) -> MachineClient | None:
        """
        Get client only if owned by owner_id (INV-13).

        Returns None if not found or not owned by the specified admin.
        """
        result = await self.db.execute(
            select(MachineClient)
            .where(MachineClient.subject_id == subject_id)
            .where(MachineClient.owner_id == owner_id)
        )
        return result.scalar_one_or_none()

    async def get_by_id_any_owner(self, subject_id: UUID) -> MachineClient | None:
        """Get client by ID regardless of owner. For internal use only."""
        result = await self.db.execute(
            select(MachineClient).where(MachineClient.subject_id == subject_id)
        )
        return result.scalar_one_or_none()

    async def list_by_owner(
        self,
        owner_id: UUID,
        status: MachineClientStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[MachineClient], int]:
        """
        List clients owned by admin with pagination (INV-13).

        Returns:
            Tuple of (list of clients, total count)
        """
        # Build base query
        base_query = select(MachineClient).where(MachineClient.owner_id == owner_id)

        if status is not None:
            base_query = base_query.where(MachineClient.status == status.value)

        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar_one()

        # Get paginated results
        query = base_query.order_by(MachineClient.created_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(query)
        clients = list(result.scalars().all())

        return clients, total

    async def create(self, client: MachineClient) -> MachineClient:
        """Create a new machine client."""
        self.db.add(client)
        await self.db.flush()
        return client

    async def update(self, client: MachineClient) -> MachineClient:
        """Update an existing machine client."""
        await self.db.flush()
        return client


class AuditLogRepository:
    """Repository for writing audit events (INV-14: no update/delete)."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, event: IdentityAuditLog) -> None:
        """
        Write audit event.

        Note: No update or delete methods exist to enforce INV-14 (immutability).
        """
        self.db.add(event)
        await self.db.flush()


# ============================================================================
# Phase 3: Certificate Request and Issued Certificate Repositories
# ============================================================================


class CertificateRequestRepository:
    """Repository for CertificateRequest CRUD operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, request: CertificateRequest) -> CertificateRequest:
        """Create a new certificate request."""
        self.db.add(request)
        await self.db.flush()
        return request

    async def get_by_id(self, request_id: UUID) -> CertificateRequest | None:
        """Get request by ID (for approvers - any owner)."""
        result = await self.db.execute(
            select(CertificateRequest)
            .options(joinedload(CertificateRequest.client).joinedload(MachineClient.owner))
            .where(CertificateRequest.request_id == request_id)
        )
        return result.scalar_one_or_none()

    async def get_by_id_for_requester(
        self, request_id: UUID, requester_id: UUID
    ) -> CertificateRequest | None:
        """Get request only if owned by requester."""
        result = await self.db.execute(
            select(CertificateRequest)
            .options(joinedload(CertificateRequest.client))
            .where(CertificateRequest.request_id == request_id)
            .where(CertificateRequest.requester_id == requester_id)
        )
        return result.scalar_one_or_none()

    async def get_by_id_for_client_owner(
        self, request_id: UUID, client_id: UUID, owner_id: UUID
    ) -> CertificateRequest | None:
        """Get request for a client owned by owner."""
        result = await self.db.execute(
            select(CertificateRequest)
            .join(MachineClient, CertificateRequest.client_id == MachineClient.subject_id)
            .where(CertificateRequest.request_id == request_id)
            .where(CertificateRequest.client_id == client_id)
            .where(MachineClient.owner_id == owner_id)
        )
        return result.scalar_one_or_none()

    async def list_pending(
        self, limit: int = 20, offset: int = 0
    ) -> tuple[list[CertificateRequest], int]:
        """List pending requests for approvers with client/owner info."""
        base_query = (
            select(CertificateRequest)
            .options(joinedload(CertificateRequest.client).joinedload(MachineClient.owner))
            .where(CertificateRequest.status == CertificateRequestStatus.PENDING.value)
        )

        # Get total count
        count_query = (
            select(func.count())
            .select_from(CertificateRequest)
            .where(CertificateRequest.status == CertificateRequestStatus.PENDING.value)
        )
        total_result = await self.db.execute(count_query)
        total = total_result.scalar_one()

        # Get paginated results
        query = base_query.order_by(CertificateRequest.created_at.asc()).offset(offset).limit(limit)
        result = await self.db.execute(query)
        requests = list(result.scalars().unique().all())

        return requests, total

    async def list_by_client(self, client_id: UUID) -> list[CertificateRequest]:
        """List all requests for a specific client."""
        result = await self.db.execute(
            select(CertificateRequest)
            .where(CertificateRequest.client_id == client_id)
            .order_by(CertificateRequest.created_at.desc())
        )
        return list(result.scalars().all())

    async def has_pending_request(self, client_id: UUID) -> bool:
        """Check if client has a pending request (for INV-05)."""
        result = await self.db.execute(
            select(func.count())
            .select_from(CertificateRequest)
            .where(CertificateRequest.client_id == client_id)
            .where(CertificateRequest.status == CertificateRequestStatus.PENDING.value)
        )
        count = result.scalar_one()
        return count > 0

    async def update(self, request: CertificateRequest) -> CertificateRequest:
        """Update an existing certificate request."""
        await self.db.flush()
        return request

    async def cancel_pending_for_client(self, client_id: UUID) -> int:
        """Cancel all pending requests for a client (for client deletion)."""
        result = await self.db.execute(
            update(CertificateRequest)
            .where(CertificateRequest.client_id == client_id)
            .where(CertificateRequest.status == CertificateRequestStatus.PENDING.value)
            .values(status=CertificateRequestStatus.CANCELLED.value)
            .returning(CertificateRequest.request_id)
        )
        cancelled_ids = list(result.scalars().all())
        return len(cancelled_ids)


class IssuedCertificateRepository:
    """Repository for IssuedCertificate tracking and revocation."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, cert: IssuedCertificate) -> IssuedCertificate:
        """Create a new issued certificate record."""
        self.db.add(cert)
        await self.db.flush()
        return cert

    async def get_by_serial(self, serial: str) -> IssuedCertificate | None:
        """Get certificate by serial number."""
        result = await self.db.execute(
            select(IssuedCertificate).where(IssuedCertificate.serial_number == serial)
        )
        return result.scalar_one_or_none()

    async def get_by_thumbprint(self, thumbprint: str) -> IssuedCertificate | None:
        """Get certificate by thumbprint."""
        result = await self.db.execute(
            select(IssuedCertificate).where(IssuedCertificate.thumbprint == thumbprint)
        )
        return result.scalar_one_or_none()

    async def get_active_by_client(self, client_id: UUID) -> IssuedCertificate | None:
        """Get current active (non-revoked) certificate for a client."""
        result = await self.db.execute(
            select(IssuedCertificate)
            .where(IssuedCertificate.client_id == client_id)
            .where(IssuedCertificate.revoked_at.is_(None))
            .order_by(IssuedCertificate.issued_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def revoke(self, certificate_id: UUID, reason: str) -> None:
        """Revoke a certificate by ID."""
        await self.db.execute(
            update(IssuedCertificate)
            .where(IssuedCertificate.certificate_id == certificate_id)
            .values(revoked_at=datetime.now(timezone.utc), revocation_reason=reason)
        )

    async def revoke_all_for_client(self, client_id: UUID, reason: str) -> int:
        """Revoke all certificates for a client (for client deletion)."""
        result = await self.db.execute(
            update(IssuedCertificate)
            .where(IssuedCertificate.client_id == client_id)
            .where(IssuedCertificate.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc), revocation_reason=reason)
            .returning(IssuedCertificate.certificate_id)
        )
        revoked_ids = list(result.scalars().all())
        return len(revoked_ids)

    async def is_revoked(self, serial: str) -> bool:
        """Check if a certificate is revoked by serial number."""
        result = await self.db.execute(
            select(IssuedCertificate.revoked_at).where(IssuedCertificate.serial_number == serial)
        )
        cert = result.scalar_one_or_none()
        if cert is None:
            return False  # Certificate not found - let caller handle
        return cert is not None  # revoked_at is set
