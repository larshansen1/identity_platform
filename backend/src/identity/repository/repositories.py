"""Repository layer for Identity module data access."""

import logging
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from identity.domain.models import (
    AdminUser,
    IdentityAuditLog,
    MachineClient,
)
from identity.domain.states import AdminRole, MachineClientStatus

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
