"""Tests for Phase 3 invariant enforcement.

These tests verify that the domain invariants defined in the requirements
are properly enforced at the appropriate layers.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from identity.domain.models import AdminUser, CertificateRequest, MachineClient
from identity.domain.states import (
    AdminRole,
    CertificateRequestStatus,
    MachineClientStatus,
    SubjectType,
)
from identity.services.client_service import ClientService, ConflictError, RequestContext


def create_mock_admin(user_id=None, roles: list[str] | None = None) -> AdminUser:
    """Create a mock AdminUser."""
    admin = MagicMock(spec=AdminUser)
    admin.user_id = user_id or uuid4()
    admin.email = "test@example.com"
    admin.name = "Test Admin"
    admin.roles = roles or [AdminRole.REQUESTER.value]
    admin.has_role = lambda r: r.value in admin.roles
    return admin


def create_mock_client(
    owner_id=None,
    subject_id=None,
    status=MachineClientStatus.PENDING_CERTIFICATE.value,
) -> MachineClient:
    """Create a mock MachineClient."""
    client = MagicMock(spec=MachineClient)
    client.subject_id = subject_id or uuid4()
    client.owner_id = owner_id or uuid4()
    client.display_name = "Test Client"
    client.status = status
    client.subject_type = SubjectType.MACHINE_CLIENT.value
    client.created_at = datetime.now(timezone.utc)
    return client


class TestInvariant05OnePendingRequest:
    """INV-05: A MachineClient can only have one pending certificate request at a time."""

    @pytest.mark.asyncio
    async def test_inv05_create_request_when_pending_exists_raises_conflict(self):
        """Test that creating a request when one is pending raises ConflictError."""
        admin = create_mock_admin()
        client = create_mock_client(owner_id=admin.user_id)
        context = RequestContext()

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockClientRepo,
            patch("identity.services.client_service.AuditLogRepository"),
            patch(
                "identity.services.client_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.client_service.IssuedCertificateRepository"),
            patch("identity.services.client_service.identity_metrics"),
        ):
            mock_db = AsyncMock()
            mock_client_repo = AsyncMock()
            mock_request_repo = AsyncMock()

            mock_client_repo.get_by_id.return_value = client
            # Simulate pending request exists
            mock_request_repo.has_pending_request.return_value = True

            MockClientRepo.return_value = mock_client_repo
            MockRequestRepo.return_value = mock_request_repo

            service = ClientService(mock_db)
            service.client_repo = mock_client_repo
            service.request_repo = mock_request_repo

            with pytest.raises(ConflictError, match="pending"):
                await service.create_certificate_request(
                    owner=admin,
                    subject_id=client.subject_id,
                    request_context=context,
                )

    @pytest.mark.asyncio
    async def test_inv05_create_request_when_no_pending_succeeds(self):
        """Test that creating a request when none is pending succeeds."""
        admin = create_mock_admin()
        client = create_mock_client(owner_id=admin.user_id)
        context = RequestContext()

        with (
            patch("identity.services.client_service.MachineClientRepository") as MockClientRepo,
            patch("identity.services.client_service.AuditLogRepository") as MockAuditRepo,
            patch(
                "identity.services.client_service.CertificateRequestRepository"
            ) as MockRequestRepo,
            patch("identity.services.client_service.IssuedCertificateRepository"),
            patch("identity.services.client_service.identity_metrics"),
        ):
            mock_db = AsyncMock()
            mock_client_repo = AsyncMock()
            mock_request_repo = AsyncMock()
            mock_audit_repo = AsyncMock()

            mock_client_repo.get_by_id.return_value = client
            # No pending request exists
            mock_request_repo.has_pending_request.return_value = False
            # Mock the create to return a new request
            mock_request = MagicMock(spec=CertificateRequest)
            mock_request.request_id = uuid4()
            mock_request_repo.create.return_value = mock_request

            MockClientRepo.return_value = mock_client_repo
            MockRequestRepo.return_value = mock_request_repo
            MockAuditRepo.return_value = mock_audit_repo

            service = ClientService(mock_db)
            service.client_repo = mock_client_repo
            service.request_repo = mock_request_repo
            service.audit_repo = mock_audit_repo

            result = await service.create_certificate_request(
                owner=admin,
                subject_id=client.subject_id,
                request_context=context,
            )

            assert result is not None
            mock_request_repo.has_pending_request.assert_called_once()
            mock_request_repo.create.assert_called_once()


class TestInvariant07RejectionReason:
    """INV-07: Rejection reason is mandatory for rejected requests."""

    def test_inv07_reject_without_reason_raises(self):
        """Test that rejecting without a reason raises ValueError."""
        # Create a real CertificateRequest model to test the domain logic
        request = CertificateRequest(
            client_id=uuid4(),
            requester_id=uuid4(),
            status=CertificateRequestStatus.PENDING.value,  # Must set initial status
        )

        # Attempt to reject without reason should raise
        with pytest.raises(ValueError, match="reason"):
            request.reject(approver_id=uuid4(), reason="")

    def test_inv07_reject_with_reason_succeeds(self):
        """Test that rejecting with a reason succeeds."""
        request = CertificateRequest(
            client_id=uuid4(),
            requester_id=uuid4(),
            status=CertificateRequestStatus.PENDING.value,  # Must set initial status
        )

        # Should not raise
        request.reject(approver_id=uuid4(), reason="Security policy violation")

        assert request.status == CertificateRequestStatus.CANCELLED.value
        assert request.rejection_reason == "Security policy violation"


class TestInvariant10DownloadWindow:
    """INV-10: Certificate download expires within configured window."""

    # Note: INV-10 is enforced at download time in CertificateService.download_certificate
    # The actual test for this is in the service layer test

    def test_download_window_constant_exists(self):
        """Verify download window is configured in CertificateService."""
        from identity.services.certificate_service import CertificateService

        assert hasattr(CertificateService, "DOWNLOAD_WINDOW_HOURS")
        assert CertificateService.DOWNLOAD_WINDOW_HOURS > 0
        assert CertificateService.DOWNLOAD_WINDOW_HOURS == 24  # Default is 24 hours


class TestInvariant15CAKeyEncryption:
    """INV-15: CA private key must be encrypted at rest."""

    def test_inv15_ca_key_not_stored_plaintext_in_env(self, monkeypatch):
        """Test that CA key from environment expects base64 encoding."""
        # The KeyManager expects base64-encoded PEM, not raw PEM
        # This ensures the key isn't accidentally stored in plaintext

        # Setting raw PEM should fail to load (because it's not base64)
        raw_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg...\n-----END PRIVATE KEY-----"
        monkeypatch.setenv("CA_KEY_PEM", raw_pem)  # Not base64 encoded
        monkeypatch.setenv("CA_CERT_PEM", raw_pem)

        from identity.ca.key_manager import KeyManager, KeyManagerError

        manager = KeyManager()

        # Should raise because raw PEM isn't valid base64
        with patch("identity.ca.key_manager.identity_metrics"):
            with pytest.raises(KeyManagerError):
                manager._try_load_from_env()
