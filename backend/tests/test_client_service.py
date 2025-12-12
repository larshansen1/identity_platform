"""Tests for ClientService business logic."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from identity.domain.models import AdminUser, MachineClient
from identity.domain.states import AdminRole, MachineClientStatus, SubjectType
from identity.services.client_service import (
    ClientService,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RequestContext,
)


def create_mock_admin(roles: list[str] | None = None) -> AdminUser:
    """Create a mock AdminUser for testing."""
    admin = MagicMock(spec=AdminUser)
    admin.user_id = uuid4()
    admin.email = "test@example.com"
    admin.name = "Test Admin"
    admin.roles = roles or [AdminRole.REQUESTER.value]
    admin.has_role = lambda r: r.value in admin.roles
    return admin


def create_mock_client(
    owner_id=None, status=MachineClientStatus.PENDING_CERTIFICATE.value
) -> MachineClient:
    """Create a mock MachineClient for testing."""
    client = MagicMock(spec=MachineClient)
    client.subject_id = uuid4()
    client.owner_id = owner_id or uuid4()
    client.display_name = "Test Client"
    client.description = None
    client.status = status
    client.subject_type = SubjectType.MACHINE_CLIENT.value
    client.certificate_thumbprint = None
    client.certificate_not_after = None
    client.created_at = datetime.now(timezone.utc)
    return client


class TestClientServiceCreate:
    """Tests for create_machine_client."""

    @pytest.mark.asyncio
    async def test_create_machine_client_success(self):
        """Test successful client creation."""
        admin = create_mock_admin([AdminRole.REQUESTER.value])
        context = RequestContext(ip_address="127.0.0.1")

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockRepo,
            patch("identity.services.client_service.AuditLogRepository") as MockAuditRepo,
            patch("identity.services.client_service.identity_metrics"),
        ):
            mock_db = AsyncMock()
            mock_repo = AsyncMock()
            mock_audit_repo = AsyncMock()

            # Configure create to return a client
            created_client = create_mock_client(owner_id=admin.user_id)
            mock_repo.create.return_value = created_client

            MockRepo.return_value = mock_repo
            MockAuditRepo.return_value = mock_audit_repo

            service = ClientService(mock_db)
            service.client_repo = mock_repo
            service.audit_repo = mock_audit_repo

            result = await service.create_machine_client(
                owner=admin,
                display_name="My Client",
                description="Test description",
                request_context=context,
            )

            assert result == created_client
            mock_repo.create.assert_called_once()
            mock_audit_repo.create.assert_called_once()
            mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_requires_requester_role(self):
        """Test that creation requires REQUESTER role."""
        admin = create_mock_admin([AdminRole.APPROVER.value])  # No REQUESTER
        context = RequestContext()

        with (
            patch("identity.services.client_service.MachineClientRepository"),
            patch("identity.services.client_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            service = ClientService(mock_db)

            with pytest.raises(ForbiddenError, match="REQUESTER role"):
                await service.create_machine_client(
                    owner=admin,
                    display_name="My Client",
                    description=None,
                    request_context=context,
                )


class TestClientServiceList:
    """Tests for list_machine_clients."""

    @pytest.mark.asyncio
    async def test_list_returns_clients(self):
        """Test listing clients for an owner."""
        admin = create_mock_admin()

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockRepo,
            patch("identity.services.client_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_repo = AsyncMock()

            clients = [create_mock_client(owner_id=admin.user_id) for _ in range(3)]
            mock_repo.list_by_owner.return_value = (clients, 3)

            MockRepo.return_value = mock_repo

            service = ClientService(mock_db)
            service.client_repo = mock_repo

            result, total = await service.list_machine_clients(
                owner=admin,
                status=None,
                limit=20,
                offset=0,
            )

            assert len(result) == 3
            assert total == 3
            mock_repo.list_by_owner.assert_called_once_with(
                owner_id=admin.user_id,
                status=None,
                limit=20,
                offset=0,
            )


class TestClientServiceGet:
    """Tests for get_machine_client."""

    @pytest.mark.asyncio
    async def test_get_owned_client_success(self):
        """Test getting an owned client."""
        admin = create_mock_admin()
        client = create_mock_client(owner_id=admin.user_id)

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockRepo,
            patch("identity.services.client_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_repo = AsyncMock()
            mock_repo.get_by_id.return_value = client

            MockRepo.return_value = mock_repo

            service = ClientService(mock_db)
            service.client_repo = mock_repo

            result = await service.get_machine_client(
                owner=admin,
                subject_id=client.subject_id,
            )

            assert result == client

    @pytest.mark.asyncio
    async def test_get_unowned_client_raises_not_found(self):
        """Test that getting an unowned client raises NotFoundError (INV-13)."""
        admin = create_mock_admin()

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockRepo,
            patch("identity.services.client_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_repo = AsyncMock()
            mock_repo.get_by_id.return_value = None  # Not found or not owned

            MockRepo.return_value = mock_repo

            service = ClientService(mock_db)
            service.client_repo = mock_repo

            with pytest.raises(NotFoundError):
                await service.get_machine_client(
                    owner=admin,
                    subject_id=uuid4(),
                )


class TestClientServiceDelete:
    """Tests for delete_machine_client."""

    @pytest.mark.asyncio
    async def test_delete_sets_revoked_status(self):
        """Test that delete revokes the client."""
        admin = create_mock_admin([AdminRole.REQUESTER.value])
        client = create_mock_client(
            owner_id=admin.user_id,
            status=MachineClientStatus.ACTIVE.value,
        )
        context = RequestContext()

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockRepo,
            patch("identity.services.client_service.AuditLogRepository") as MockAuditRepo,
            patch(
                "identity.services.client_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.client_service.IssuedCertificateRepository") as MockCertRepo,
            patch("identity.services.client_service.identity_metrics"),
        ):
            mock_db = AsyncMock()
            mock_repo = AsyncMock()
            mock_audit_repo = AsyncMock()
            mock_request_repo = AsyncMock()
            mock_cert_repo = AsyncMock()
            mock_repo.get_by_id.return_value = client

            # Configure new repos
            mock_request_repo.cancel_pending_for_client.return_value = 0
            mock_cert_repo.revoke_all_for_client.return_value = 0

            MockRepo.return_value = mock_repo
            MockAuditRepo.return_value = mock_audit_repo
            MockRequestRepo.return_value = mock_request_repo
            MockCertRepo.return_value = mock_cert_repo

            service = ClientService(mock_db)
            service.client_repo = mock_repo
            service.audit_repo = mock_audit_repo
            service.request_repo = mock_request_repo
            service.cert_repo = mock_cert_repo

            await service.delete_machine_client(
                owner=admin,
                subject_id=client.subject_id,
                request_context=context,
            )

            client.revoke.assert_called_once()
            mock_repo.update.assert_called_once()
            mock_audit_repo.create.assert_called_once()
            mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_revoked_client_raises_conflict(self):
        """Test that deleting already revoked client raises ConflictError (INV-04)."""
        admin = create_mock_admin([AdminRole.REQUESTER.value])
        client = create_mock_client(
            owner_id=admin.user_id,
            status=MachineClientStatus.REVOKED.value,
        )
        context = RequestContext()

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockRepo,
            patch("identity.services.client_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_repo = AsyncMock()
            mock_repo.get_by_id.return_value = client

            MockRepo.return_value = mock_repo

            service = ClientService(mock_db)
            service.client_repo = mock_repo

            with pytest.raises(ConflictError, match="already revoked"):
                await service.delete_machine_client(
                    owner=admin,
                    subject_id=client.subject_id,
                    request_context=context,
                )

    @pytest.mark.asyncio
    async def test_delete_requires_requester_role(self):
        """Test that delete requires REQUESTER role."""
        admin = create_mock_admin([AdminRole.APPROVER.value])  # No REQUESTER
        context = RequestContext()

        with (
            patch("identity.services.client_service.MachineClientRepository"),
            patch("identity.services.client_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            service = ClientService(mock_db)

            with pytest.raises(ForbiddenError, match="REQUESTER role"):
                await service.delete_machine_client(
                    owner=admin,
                    subject_id=uuid4(),
                    request_context=context,
                )
