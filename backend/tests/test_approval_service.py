"""Unit tests for ApprovalService and related invariants."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from identity.domain.models import AdminUser, CertificateRequest, MachineClient
from identity.domain.states import (
    AdminRole,
    CertificateRequestStatus,
    CertificateRequestType,
    MachineClientStatus,
    SubjectType,
)
from identity.services.approval_service import ApprovalService, SelfApprovalError
from identity.services.client_service import (
    ConflictError,
    NotFoundError,
    RequestContext,
)


def create_mock_admin(
    user_id=None, roles: list[str] | None = None, email: str = "admin@example.com"
) -> AdminUser:
    """Create a mock AdminUser for testing."""
    admin = MagicMock(spec=AdminUser)
    admin.user_id = user_id or uuid4()
    admin.email = email
    admin.name = "Test Admin"
    admin.roles = roles or [AdminRole.APPROVER.value]
    admin.has_role = lambda r: r.value in admin.roles
    return admin


def create_mock_client(
    owner_id=None,
    subject_id=None,
    status=MachineClientStatus.PENDING_CERTIFICATE.value,
) -> MachineClient:
    """Create a mock MachineClient for testing."""
    client = MagicMock(spec=MachineClient)
    client.subject_id = subject_id or uuid4()
    client.owner_id = owner_id or uuid4()
    client.display_name = "Test Client"
    client.description = None
    client.status = status
    client.subject_type = SubjectType.MACHINE_CLIENT.value
    client.certificate_thumbprint = None
    client.certificate_not_after = None
    client.created_at = datetime.now(timezone.utc)
    client.owner = create_mock_admin(user_id=client.owner_id)
    return client


def create_mock_request(
    client: MachineClient,
    requester_id=None,
    status=CertificateRequestStatus.PENDING.value,
) -> CertificateRequest:
    """Create a mock CertificateRequest for testing."""
    request = MagicMock(spec=CertificateRequest)
    request.request_id = uuid4()
    request.client_id = client.subject_id
    request.requester_id = requester_id or client.owner_id
    request.status = status
    request.request_type = CertificateRequestType.INITIAL.value
    request.certificate_pem = None
    request.private_key_pem_encrypted = None
    request.rejection_reason = None
    request.approved_by_id = None
    request.download_expires_at = None
    request.created_at = datetime.now(timezone.utc)
    request.client = client
    return request


class TestApprovalServiceListPending:
    """Tests for ApprovalService.list_pending."""

    @pytest.mark.asyncio
    async def test_list_pending_returns_pending_requests(self):
        """Test listing pending requests."""
        client = create_mock_client()
        request = create_mock_request(client)

        with (
            patch(
                "identity.services.approval_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.approval_service.MachineClientRepository"),
            patch("identity.services.approval_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_key_manager = MagicMock()
            mock_request_repo = AsyncMock()
            mock_request_repo.list_pending.return_value = ([request], 1)
            MockRequestRepo.return_value = mock_request_repo

            service = ApprovalService(mock_db, mock_key_manager)
            service.request_repo = mock_request_repo

            result, total = await service.list_pending()

            assert total == 1
            assert len(result) == 1
            assert result[0]["request_id"] == str(request.request_id)


class TestApprovalServiceApprove:
    """Tests for ApprovalService.approve."""

    @pytest.mark.asyncio
    async def test_approve_success(self):
        """Test successful request approval."""
        approver = create_mock_admin()
        owner = create_mock_admin()
        client = create_mock_client(owner_id=owner.user_id)
        request = create_mock_request(client)
        context = RequestContext()

        with (
            patch(
                "identity.services.approval_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.approval_service.MachineClientRepository") as MockClientRepo,
            patch("identity.services.approval_service.AuditLogRepository") as MockAuditRepo,
            patch("identity.services.approval_service.CertificateService"),
            patch("identity.services.approval_service.identity_metrics"),
        ):
            mock_db = AsyncMock()
            mock_key_manager = MagicMock()
            mock_request_repo = AsyncMock()
            mock_client_repo = AsyncMock()
            mock_audit_repo = AsyncMock()
            mock_cert_service = AsyncMock()

            mock_request_repo.get_by_id.return_value = request
            mock_client_repo.get_by_id_any_owner.return_value = client
            MockRequestRepo.return_value = mock_request_repo
            MockClientRepo.return_value = mock_client_repo
            MockAuditRepo.return_value = mock_audit_repo

            service = ApprovalService(mock_db, mock_key_manager)
            service.request_repo = mock_request_repo
            service.client_repo = mock_client_repo
            service.audit_repo = mock_audit_repo
            service._cert_service = mock_cert_service

            await service.approve(approver, request.request_id, context)

            request.approve.assert_called_once()
            mock_audit_repo.create.assert_called_once()
            mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_inv06_self_approval_raises_error(self):
        """Test INV-06: Approver cannot approve their own client's request."""
        owner = create_mock_admin()
        # Same person is both owner and approver
        client = create_mock_client(owner_id=owner.user_id)
        request = create_mock_request(client)
        context = RequestContext()

        with (
            patch(
                "identity.services.approval_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.approval_service.MachineClientRepository") as MockClientRepo,
            patch("identity.services.approval_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_key_manager = MagicMock()
            mock_request_repo = AsyncMock()
            mock_client_repo = AsyncMock()

            mock_request_repo.get_by_id.return_value = request
            mock_client_repo.get_by_id_any_owner.return_value = client
            MockRequestRepo.return_value = mock_request_repo
            MockClientRepo.return_value = mock_client_repo

            service = ApprovalService(mock_db, mock_key_manager)
            service.request_repo = mock_request_repo
            service.client_repo = mock_client_repo

            with pytest.raises(SelfApprovalError, match="INV-06"):
                await service.approve(owner, request.request_id, context)

    @pytest.mark.asyncio
    async def test_approve_not_pending_raises_conflict(self):
        """Test that approving a non-pending request raises ConflictError."""
        approver = create_mock_admin()
        owner = create_mock_admin()
        client = create_mock_client(owner_id=owner.user_id)
        request = create_mock_request(client, status=CertificateRequestStatus.ISSUED.value)
        context = RequestContext()

        with (
            patch(
                "identity.services.approval_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.approval_service.MachineClientRepository"),
            patch("identity.services.approval_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_key_manager = MagicMock()
            mock_request_repo = AsyncMock()

            mock_request_repo.get_by_id.return_value = request
            MockRequestRepo.return_value = mock_request_repo

            service = ApprovalService(mock_db, mock_key_manager)
            service.request_repo = mock_request_repo

            with pytest.raises(ConflictError, match="not pending"):
                await service.approve(approver, request.request_id, context)

    @pytest.mark.asyncio
    async def test_approve_not_found_raises_error(self):
        """Test that approving a non-existent request raises NotFoundError."""
        approver = create_mock_admin()
        context = RequestContext()

        with (
            patch(
                "identity.services.approval_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.approval_service.MachineClientRepository"),
            patch("identity.services.approval_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_key_manager = MagicMock()
            mock_request_repo = AsyncMock()

            mock_request_repo.get_by_id.return_value = None
            MockRequestRepo.return_value = mock_request_repo

            service = ApprovalService(mock_db, mock_key_manager)
            service.request_repo = mock_request_repo

            with pytest.raises(NotFoundError):
                await service.approve(approver, uuid4(), context)


class TestApprovalServiceReject:
    """Tests for ApprovalService.reject."""

    @pytest.mark.asyncio
    async def test_reject_success(self):
        """Test successful request rejection."""
        approver = create_mock_admin()
        owner = create_mock_admin()
        client = create_mock_client(owner_id=owner.user_id)
        request = create_mock_request(client)
        context = RequestContext()
        reason = "Security review required"

        with (
            patch(
                "identity.services.approval_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.approval_service.MachineClientRepository"),
            patch("identity.services.approval_service.AuditLogRepository") as MockAuditRepo,
            patch("identity.services.approval_service.identity_metrics"),
        ):
            mock_db = AsyncMock()
            mock_key_manager = MagicMock()
            mock_request_repo = AsyncMock()
            mock_audit_repo = AsyncMock()

            mock_request_repo.get_by_id.return_value = request
            MockRequestRepo.return_value = mock_request_repo
            MockAuditRepo.return_value = mock_audit_repo

            service = ApprovalService(mock_db, mock_key_manager)
            service.request_repo = mock_request_repo
            service.audit_repo = mock_audit_repo

            await service.reject(approver, request.request_id, reason, context)

            request.reject.assert_called_once_with(approver_id=approver.user_id, reason=reason)
            mock_audit_repo.create.assert_called_once()
            mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_reject_not_pending_raises_conflict(self):
        """Test that rejecting a non-pending request raises ConflictError."""
        approver = create_mock_admin()
        client = create_mock_client()
        request = create_mock_request(client, status=CertificateRequestStatus.COMPLETED.value)
        context = RequestContext()

        with (
            patch(
                "identity.services.approval_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.approval_service.MachineClientRepository"),
            patch("identity.services.approval_service.AuditLogRepository"),
        ):
            mock_db = AsyncMock()
            mock_key_manager = MagicMock()
            mock_request_repo = AsyncMock()

            mock_request_repo.get_by_id.return_value = request
            MockRequestRepo.return_value = mock_request_repo

            service = ApprovalService(mock_db, mock_key_manager)
            service.request_repo = mock_request_repo

            with pytest.raises(ConflictError, match="not pending"):
                await service.reject(approver, request.request_id, "reason", context)
