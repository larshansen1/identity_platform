"""Structural and transition tests for state machines.

Per state machine rules, these tests verify:
1. All states have handlers
2. Handler naming convention
3. One test per transition table entry
4. One test per invariant
"""

import pytest

from identity.domain.state_machine import InvalidTransitionError
from identity.domain.state_machines import (
    CertificateRequestStateMachine,
    MachineClientStateMachine,
)
from identity.domain.states import (
    CertificateRequestEvent,
    CertificateRequestStatus,
    MachineClientEvent,
    MachineClientStatus,
)

# =============================================================================
# Structural Tests - MachineClient
# =============================================================================


class TestMachineClientStateMachineStructure:
    """Structural tests for MachineClientStateMachine."""

    def test_all_non_terminal_states_have_transitions(self):
        """Every non-terminal state must have at least one transition out."""
        terminal_states = {MachineClientStatus.REVOKED}
        non_terminal_states = set(MachineClientStatus) - terminal_states

        covered_states = {state for state, _ in MachineClientStateMachine.TRANSITIONS.keys()}

        for state in non_terminal_states:
            assert state in covered_states, f"Non-terminal state {state} has no transitions"

    def test_terminal_state_has_no_transitions(self):
        """REVOKED is terminal - must have no transitions out (INV-04)."""
        terminal_state = MachineClientStatus.REVOKED

        transitions_from_terminal = [
            (s, e) for s, e in MachineClientStateMachine.TRANSITIONS.keys() if s == terminal_state
        ]

        assert len(transitions_from_terminal) == 0, (
            f"Terminal state {terminal_state} should have no transitions, "
            f"found: {transitions_from_terminal}"
        )

    def test_all_events_are_used(self):
        """Every event in enum must be used in at least one transition."""
        used_events = {event for _, event in MachineClientStateMachine.TRANSITIONS.keys()}

        for event in MachineClientEvent:
            assert event in used_events, f"Event {event} is never used in transitions"


# =============================================================================
# Transition Tests - MachineClient
# =============================================================================


class TestMachineClientTransitions:
    """One test per entry in MachineClient transition table."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock MachineClient entity."""
        from unittest.mock import MagicMock

        client = MagicMock()
        client.subject_id = "test-client-id"
        client.status = MachineClientStatus.PENDING_CERTIFICATE.value
        client.certificate_thumbprint = None
        client.certificate_serial = None
        client.certificate_not_before = None
        client.certificate_not_after = None
        return client

    def test_pending_certificate_installed_to_active(self, mock_client):
        """(PENDING_CERTIFICATE, CERTIFICATE_INSTALLED) -> ACTIVE"""
        mock_client.status = MachineClientStatus.PENDING_CERTIFICATE.value
        sm = MachineClientStateMachine(mock_client)

        new_state = sm.transition(MachineClientEvent.CERTIFICATE_INSTALLED)

        assert new_state == MachineClientStatus.ACTIVE
        assert mock_client.status == MachineClientStatus.ACTIVE.value

    def test_pending_revocation_to_revoked(self, mock_client):
        """(PENDING_CERTIFICATE, REVOCATION_REQUESTED) -> REVOKED"""
        mock_client.status = MachineClientStatus.PENDING_CERTIFICATE.value
        sm = MachineClientStateMachine(mock_client)

        new_state = sm.transition(MachineClientEvent.REVOCATION_REQUESTED)

        assert new_state == MachineClientStatus.REVOKED
        assert mock_client.status == MachineClientStatus.REVOKED.value

    def test_active_certificate_installed_to_active(self, mock_client):
        """(ACTIVE, CERTIFICATE_INSTALLED) -> ACTIVE (renewal)"""
        mock_client.status = MachineClientStatus.ACTIVE.value
        sm = MachineClientStateMachine(mock_client)

        new_state = sm.transition(MachineClientEvent.CERTIFICATE_INSTALLED)

        assert new_state == MachineClientStatus.ACTIVE
        assert mock_client.status == MachineClientStatus.ACTIVE.value

    def test_active_revocation_to_revoked(self, mock_client):
        """(ACTIVE, REVOCATION_REQUESTED) -> REVOKED"""
        mock_client.status = MachineClientStatus.ACTIVE.value
        sm = MachineClientStateMachine(mock_client)

        new_state = sm.transition(MachineClientEvent.REVOCATION_REQUESTED)

        assert new_state == MachineClientStatus.REVOKED
        assert mock_client.status == MachineClientStatus.REVOKED.value


# =============================================================================
# Invariant Tests - MachineClient
# =============================================================================


class TestMachineClientInvariants:
    """Invariant tests for MachineClient state machine."""

    @pytest.fixture
    def mock_client(self):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.subject_id = "test-client-id"
        return client

    def test_inv04_revoked_is_terminal(self, mock_client):
        """INV-04: REVOKED allows no transitions."""
        mock_client.status = MachineClientStatus.REVOKED.value
        sm = MachineClientStateMachine(mock_client)

        for event in MachineClientEvent:
            with pytest.raises(InvalidTransitionError):
                sm.transition(event)


# =============================================================================
# Structural Tests - CertificateRequest
# =============================================================================


class TestCertificateRequestStateMachineStructure:
    """Structural tests for CertificateRequestStateMachine."""

    def test_all_non_terminal_states_have_transitions(self):
        """Every non-terminal state must have at least one transition out."""
        terminal_states = {CertificateRequestStatus.COMPLETED, CertificateRequestStatus.CANCELLED}
        non_terminal_states = set(CertificateRequestStatus) - terminal_states

        covered_states = {state for state, _ in CertificateRequestStateMachine.TRANSITIONS.keys()}

        for state in non_terminal_states:
            assert state in covered_states, f"Non-terminal state {state} has no transitions"

    def test_terminal_states_have_no_transitions(self):
        """COMPLETED and CANCELLED are terminal - must have no transitions out (INV-08, INV-09)."""
        terminal_states = {CertificateRequestStatus.COMPLETED, CertificateRequestStatus.CANCELLED}

        for terminal_state in terminal_states:
            transitions_from_terminal = [
                (s, e)
                for s, e in CertificateRequestStateMachine.TRANSITIONS.keys()
                if s == terminal_state
            ]

            assert len(transitions_from_terminal) == 0, (
                f"Terminal state {terminal_state} should have no transitions, "
                f"found: {transitions_from_terminal}"
            )

    def test_all_events_are_used(self):
        """Every event in enum must be used in at least one transition."""
        used_events = {event for _, event in CertificateRequestStateMachine.TRANSITIONS.keys()}

        for event in CertificateRequestEvent:
            assert event in used_events, f"Event {event} is never used in transitions"


# =============================================================================
# Transition Tests - CertificateRequest
# =============================================================================


class TestCertificateRequestTransitions:
    """One test per entry in CertificateRequest transition table."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock CertificateRequest entity."""
        from unittest.mock import MagicMock

        request = MagicMock()
        request.request_id = "test-request-id"
        request.status = CertificateRequestStatus.PENDING.value
        return request

    def test_pending_approved_to_issued(self, mock_request):
        """(PENDING, APPROVED) -> ISSUED"""
        mock_request.status = CertificateRequestStatus.PENDING.value
        sm = CertificateRequestStateMachine(mock_request)

        new_state = sm.transition(CertificateRequestEvent.APPROVED)

        assert new_state == CertificateRequestStatus.ISSUED
        assert mock_request.status == CertificateRequestStatus.ISSUED.value

    def test_pending_rejected_to_cancelled(self, mock_request):
        """(PENDING, REJECTED) -> CANCELLED"""
        mock_request.status = CertificateRequestStatus.PENDING.value
        sm = CertificateRequestStateMachine(mock_request)

        new_state = sm.transition(CertificateRequestEvent.REJECTED)

        assert new_state == CertificateRequestStatus.CANCELLED
        assert mock_request.status == CertificateRequestStatus.CANCELLED.value

    def test_pending_cancellation_to_cancelled(self, mock_request):
        """(PENDING, CANCELLATION_REQUESTED) -> CANCELLED"""
        mock_request.status = CertificateRequestStatus.PENDING.value
        sm = CertificateRequestStateMachine(mock_request)

        new_state = sm.transition(CertificateRequestEvent.CANCELLATION_REQUESTED)

        assert new_state == CertificateRequestStatus.CANCELLED
        assert mock_request.status == CertificateRequestStatus.CANCELLED.value

    def test_issued_download_to_completed(self, mock_request):
        """(ISSUED, DOWNLOAD_COMPLETED) -> COMPLETED"""
        mock_request.status = CertificateRequestStatus.ISSUED.value
        sm = CertificateRequestStateMachine(mock_request)

        new_state = sm.transition(CertificateRequestEvent.DOWNLOAD_COMPLETED)

        assert new_state == CertificateRequestStatus.COMPLETED
        assert mock_request.status == CertificateRequestStatus.COMPLETED.value

    def test_issued_cancellation_to_cancelled(self, mock_request):
        """(ISSUED, CANCELLATION_REQUESTED) -> CANCELLED"""
        mock_request.status = CertificateRequestStatus.ISSUED.value
        sm = CertificateRequestStateMachine(mock_request)

        new_state = sm.transition(CertificateRequestEvent.CANCELLATION_REQUESTED)

        assert new_state == CertificateRequestStatus.CANCELLED
        assert mock_request.status == CertificateRequestStatus.CANCELLED.value


# =============================================================================
# Invariant Tests - CertificateRequest
# =============================================================================


class TestCertificateRequestInvariants:
    """Invariant tests for CertificateRequest state machine."""

    @pytest.fixture
    def mock_request(self):
        from unittest.mock import MagicMock

        request = MagicMock()
        request.request_id = "test-request-id"
        return request

    def test_inv08_completed_is_terminal(self, mock_request):
        """INV-08: COMPLETED allows no transitions."""
        mock_request.status = CertificateRequestStatus.COMPLETED.value
        sm = CertificateRequestStateMachine(mock_request)

        for event in CertificateRequestEvent:
            with pytest.raises(InvalidTransitionError):
                sm.transition(event)

    def test_inv09_cancelled_is_terminal(self, mock_request):
        """INV-09: CANCELLED allows no transitions."""
        mock_request.status = CertificateRequestStatus.CANCELLED.value
        sm = CertificateRequestStateMachine(mock_request)

        for event in CertificateRequestEvent:
            with pytest.raises(InvalidTransitionError):
                sm.transition(event)


# =============================================================================
# Handler Tests - MachineClient
# =============================================================================


class TestMachineClientHandlers:
    """Tests for MachineClient state machine handler methods."""

    @pytest.fixture
    def mock_client(self):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.subject_id = "test-client-id"
        client.status = MachineClientStatus.PENDING_CERTIFICATE.value
        return client

    def test_install_certificate_transitions_and_sets_fields(self, mock_client):
        """install_certificate() transitions and sets certificate fields."""
        from datetime import datetime, timezone

        sm = MachineClientStateMachine(mock_client)
        now = datetime.now(timezone.utc)

        result = sm.install_certificate(
            thumbprint="ABC123",
            serial="SER001",
            not_before=now,
            not_after=now,
        )

        assert result == MachineClientStatus.ACTIVE
        assert mock_client.certificate_thumbprint == "ABC123"
        assert mock_client.certificate_serial == "SER001"
        assert mock_client.certificate_not_before == now
        assert mock_client.certificate_not_after == now

    def test_install_certificate_fails_when_revoked(self, mock_client):
        """install_certificate() fails when client is REVOKED (INV-04)."""
        from datetime import datetime, timezone

        mock_client.status = MachineClientStatus.REVOKED.value
        sm = MachineClientStateMachine(mock_client)
        now = datetime.now(timezone.utc)

        with pytest.raises(InvalidTransitionError):
            sm.install_certificate(
                thumbprint="ABC123",
                serial="SER001",
                not_before=now,
                not_after=now,
            )

    def test_revoke_transitions_to_revoked(self, mock_client):
        """revoke() transitions to REVOKED."""
        sm = MachineClientStateMachine(mock_client)

        result = sm.revoke()

        assert result == MachineClientStatus.REVOKED
        assert mock_client.status == MachineClientStatus.REVOKED.value


# =============================================================================
# Handler Tests - CertificateRequest
# =============================================================================


class TestCertificateRequestHandlers:
    """Tests for CertificateRequest state machine handler methods."""

    @pytest.fixture
    def mock_request(self):
        from unittest.mock import MagicMock

        request = MagicMock()
        request.request_id = "test-request-id"
        request.status = CertificateRequestStatus.PENDING.value
        return request

    def test_approve_transitions_and_sets_fields(self, mock_request):
        """approve() transitions and sets certificate fields."""
        from uuid import uuid4

        sm = CertificateRequestStateMachine(mock_request)
        approver_id = uuid4()

        result = sm.approve(approver_id, "CERT_PEM", "KEY_PEM")

        assert result == CertificateRequestStatus.ISSUED
        assert mock_request.approver_id == approver_id
        assert mock_request.certificate_pem == "CERT_PEM"
        assert mock_request.private_key_pem_encrypted == "KEY_PEM"
        assert mock_request.decided_at is not None

    def test_reject_transitions_and_sets_reason(self, mock_request):
        """reject() transitions and sets rejection reason."""
        from uuid import uuid4

        sm = CertificateRequestStateMachine(mock_request)
        approver_id = uuid4()

        result = sm.reject(approver_id, "Not approved")

        assert result == CertificateRequestStatus.CANCELLED
        assert mock_request.approver_id == approver_id
        assert mock_request.rejection_reason == "Not approved"
        assert mock_request.decided_at is not None

    def test_reject_requires_reason_inv07(self, mock_request):
        """reject() requires reason (INV-07)."""
        from uuid import uuid4

        sm = CertificateRequestStateMachine(mock_request)
        approver_id = uuid4()

        with pytest.raises(ValueError, match="Rejection reason is required"):
            sm.reject(approver_id, "")

    def test_complete_download_transitions_to_completed(self, mock_request):
        """complete_download() transitions to COMPLETED."""
        mock_request.status = CertificateRequestStatus.ISSUED.value
        sm = CertificateRequestStateMachine(mock_request)

        result = sm.complete_download()

        assert result == CertificateRequestStatus.COMPLETED

    def test_cancel_transitions_to_cancelled(self, mock_request):
        """cancel() transitions to CANCELLED from PENDING."""
        sm = CertificateRequestStateMachine(mock_request)

        result = sm.cancel()

        assert result == CertificateRequestStatus.CANCELLED
