from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from identity.domain.models import AdminUser, CertificateRequest, MachineClient
from identity.domain.state_machine import InvalidTransitionError
from identity.domain.states import (
    CertificateRequestStatus,
    MachineClientStatus,
)


def utc_now():
    return datetime.now(timezone.utc)


class TestMachineClientTransitions:
    def test_install_certificate_activates_client(self):
        client = MachineClient(
            subject_id=uuid4(),
            owner_id=uuid4(),
            status=MachineClientStatus.PENDING_CERTIFICATE.value,
            subject_type="machine_client",
            display_name="Test Client",
        )

        now = utc_now()
        client.install_certificate(
            thumbprint="thumb123",
            serial="serial123",
            not_before=now,
            not_after=now + timedelta(days=365),
        )

        assert client.status == MachineClientStatus.ACTIVE.value
        assert client.certificate_thumbprint == "thumb123"

    def test_cannot_modify_revoked_client(self):
        client = MachineClient(status=MachineClientStatus.REVOKED.value)
        with pytest.raises(InvalidTransitionError):
            client.install_certificate("t", "s", utc_now(), utc_now())

    def test_is_expired_logic(self):
        client = MachineClient()
        assert not client.is_expired

        client.certificate_not_after = utc_now() - timedelta(days=1)
        assert client.is_expired

        client.certificate_not_after = utc_now() + timedelta(days=1)
        assert not client.is_expired


class TestCertificateRequestTransitions:
    def test_approve_transition(self):
        req = CertificateRequest(status=CertificateRequestStatus.PENDING.value)
        approver = uuid4()
        req.approve(approver, "cert_pem", "key_pem")

        assert req.status == CertificateRequestStatus.ISSUED.value
        assert req.approver_id == approver
        assert req.certificate_pem == "cert_pem"
        assert req.decided_at is not None

    def test_reject_transition(self):
        req = CertificateRequest(status=CertificateRequestStatus.PENDING.value)
        approver = uuid4()
        req.reject(approver, "Bad request")

        assert req.status == CertificateRequestStatus.CANCELLED.value
        assert req.rejection_reason == "Bad request"
        assert req.decided_at is not None

    def test_reject_requires_reason(self):
        req = CertificateRequest(status=CertificateRequestStatus.PENDING.value)
        with pytest.raises(ValueError, match="Rejection reason is required"):
            req.reject(uuid4(), "")

    def test_complete_download(self):
        req = CertificateRequest(status=CertificateRequestStatus.ISSUED.value)
        req.complete_download()
        assert req.status == CertificateRequestStatus.COMPLETED.value

    def test_complete_download_invalid_state(self):
        req = CertificateRequest(status=CertificateRequestStatus.PENDING.value)
        with pytest.raises(InvalidTransitionError):
            req.complete_download()

    def test_cancel_transition(self):
        req = CertificateRequest(status=CertificateRequestStatus.PENDING.value)
        req.cancel()
        assert req.status == CertificateRequestStatus.CANCELLED.value

    def test_cancel_invalid_state(self):
        req = CertificateRequest(status=CertificateRequestStatus.COMPLETED.value)
        with pytest.raises(InvalidTransitionError):
            req.cancel()

    def test_approve_invalid_state(self):
        req = CertificateRequest(status=CertificateRequestStatus.CANCELLED.value)
        with pytest.raises(InvalidTransitionError):
            req.approve(uuid4(), "cert", "key")

    def test_reject_invalid_state(self):
        req = CertificateRequest(status=CertificateRequestStatus.ISSUED.value)
        with pytest.raises(InvalidTransitionError):
            req.reject(uuid4(), "reason")


class TestMachineClientMethods:
    def test_revoke(self):
        client = MachineClient(status=MachineClientStatus.ACTIVE.value)
        client.revoke()
        assert client.status == MachineClientStatus.REVOKED.value


class TestAdminUserMethods:
    def test_has_role(self):
        from identity.domain.states import AdminRole

        user = AdminUser(roles=[AdminRole.REQUESTER.value])
        assert user.has_role(AdminRole.REQUESTER)
        assert not user.has_role(AdminRole.APPROVER)
