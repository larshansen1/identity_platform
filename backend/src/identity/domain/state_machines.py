"""State machine implementations for domain entities.

Each state machine defines:
- TRANSITIONS: explicit (state, event) -> new_state mapping
- Handlers for side effects during transitions
- Invariants documented and enforced

Invariants:
    INV-03: PENDING_CERTIFICATE transitions via CERTIFICATE_INSTALLED or REVOCATION
    INV-04: REVOKED is terminal - no transitions out
    INV-07: REJECTED event requires reason (enforced in service layer)
    INV-08: COMPLETED is terminal - no transitions out
    INV-09: CANCELLED is terminal - no transitions out
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from identity.domain.state_machine import StateMachine
from identity.domain.states import (
    CertificateRequestEvent as CREvent,
)
from identity.domain.states import (
    CertificateRequestStatus as CRStatus,
)
from identity.domain.states import (
    MachineClientEvent as MCEvent,
)
from identity.domain.states import (
    MachineClientStatus as MCStatus,
)

if TYPE_CHECKING:
    from identity.domain.models import CertificateRequest, MachineClient

# Type aliases for shorter lines
MCTransitions = dict[tuple[MCStatus, MCEvent], MCStatus]
CRTransitions = dict[tuple[CRStatus, CREvent], CRStatus]


class MachineClientStateMachine(StateMachine[MCStatus, MCEvent]):
    """State machine for MachineClient entity.

    States:
        PENDING_CERTIFICATE: Initial state, awaiting certificate issuance
        ACTIVE: Has valid certificate, can authenticate
        REVOKED: Terminal state, cannot transition out (INV-04)

    Transition Table:
        (PENDING_CERTIFICATE, CERTIFICATE_INSTALLED) -> ACTIVE
        (PENDING_CERTIFICATE, REVOCATION_REQUESTED) -> REVOKED
        (ACTIVE, CERTIFICATE_INSTALLED) -> ACTIVE  (renewal)
        (ACTIVE, REVOCATION_REQUESTED) -> REVOKED
    """

    TRANSITIONS: MCTransitions = {
        # From PENDING_CERTIFICATE
        (MCStatus.PENDING_CERTIFICATE, MCEvent.CERTIFICATE_INSTALLED): MCStatus.ACTIVE,
        (MCStatus.PENDING_CERTIFICATE, MCEvent.REVOCATION_REQUESTED): MCStatus.REVOKED,
        # From ACTIVE
        (MCStatus.ACTIVE, MCEvent.CERTIFICATE_INSTALLED): MCStatus.ACTIVE,
        (MCStatus.ACTIVE, MCEvent.REVOCATION_REQUESTED): MCStatus.REVOKED,
        # REVOKED is terminal - no transitions defined (INV-04)
    }

    def __init__(self, entity: "MachineClient"):  # noqa: F821
        self._entity = entity

    def _get_state(self) -> MCStatus:
        return MCStatus(self._entity.status)

    def _set_state(self, state: MCStatus) -> None:
        self._entity.status = state.value

    def _get_entity_id(self) -> str:
        return str(self._entity.subject_id)

    def install_certificate(
        self,
        thumbprint: str,
        serial: str,
        not_before: datetime,
        not_after: datetime,
    ) -> MCStatus:
        """Install certificate and transition to ACTIVE.

        Args:
            thumbprint: Certificate thumbprint
            serial: Certificate serial number
            not_before: Certificate validity start
            not_after: Certificate validity end

        Returns:
            New state after transition

        Raises:
            InvalidTransitionError: If client is REVOKED
        """
        # Execute transition (will raise if invalid)
        new_state = self.transition(MCEvent.CERTIFICATE_INSTALLED)

        # Side effects after successful transition
        self._entity.certificate_thumbprint = thumbprint
        self._entity.certificate_serial = serial
        self._entity.certificate_not_before = not_before
        self._entity.certificate_not_after = not_after

        return new_state

    def revoke(self) -> MCStatus:
        """Revoke the client.

        Returns:
            New state (REVOKED)

        Raises:
            InvalidTransitionError: If already REVOKED
        """
        return self.transition(MCEvent.REVOCATION_REQUESTED)


class CertificateRequestStateMachine(StateMachine[CRStatus, CREvent]):
    """State machine for CertificateRequest entity.

    States:
        PENDING: Awaiting approval
        ISSUED: Approved and certificate generated, awaiting download
        COMPLETED: Downloaded, terminal state (INV-08)
        CANCELLED: Rejected or cancelled, terminal state (INV-09)

    Transition Table:
        (PENDING, APPROVED) -> ISSUED
        (PENDING, REJECTED) -> CANCELLED
        (PENDING, CANCELLATION_REQUESTED) -> CANCELLED
        (ISSUED, DOWNLOAD_COMPLETED) -> COMPLETED
        (ISSUED, CANCELLATION_REQUESTED) -> CANCELLED
    """

    TRANSITIONS: CRTransitions = {
        # From PENDING
        (CRStatus.PENDING, CREvent.APPROVED): CRStatus.ISSUED,
        (CRStatus.PENDING, CREvent.REJECTED): CRStatus.CANCELLED,
        (CRStatus.PENDING, CREvent.CANCELLATION_REQUESTED): CRStatus.CANCELLED,
        # From ISSUED
        (CRStatus.ISSUED, CREvent.DOWNLOAD_COMPLETED): CRStatus.COMPLETED,
        (CRStatus.ISSUED, CREvent.CANCELLATION_REQUESTED): CRStatus.CANCELLED,
        # COMPLETED and CANCELLED are terminal (INV-08, INV-09)
    }

    def __init__(self, entity: "CertificateRequest"):  # noqa: F821
        self._entity = entity

    def _get_state(self) -> CRStatus:
        return CRStatus(self._entity.status)

    def _set_state(self, state: CRStatus) -> None:
        self._entity.status = state.value

    def _get_entity_id(self) -> str:
        return str(self._entity.request_id)

    def approve(
        self,
        approver_id: UUID,
        certificate_pem: str,
        private_key_pem_encrypted: str,
    ) -> CRStatus:
        """Approve the request and issue certificate.

        Args:
            approver_id: ID of admin approving
            certificate_pem: Generated certificate PEM
            private_key_pem_encrypted: Encrypted private key PEM

        Returns:
            New state (ISSUED)

        Raises:
            InvalidTransitionError: If not in PENDING state
        """
        from identity.domain.models import utc_now

        new_state = self.transition(CREvent.APPROVED)

        # Side effects
        self._entity.approver_id = approver_id
        self._entity.certificate_pem = certificate_pem
        self._entity.private_key_pem_encrypted = private_key_pem_encrypted
        self._entity.decided_at = utc_now()

        return new_state

    def reject(self, approver_id: UUID, reason: str) -> CRStatus:
        """Reject the request.

        Args:
            approver_id: ID of admin rejecting
            reason: Rejection reason (required per INV-07)

        Returns:
            New state (CANCELLED)

        Raises:
            InvalidTransitionError: If not in PENDING state
            ValueError: If reason is empty
        """
        from identity.domain.models import utc_now

        if not reason:
            raise ValueError("Rejection reason is required (INV-07)")

        new_state = self.transition(CREvent.REJECTED)

        # Side effects
        self._entity.approver_id = approver_id
        self._entity.rejection_reason = reason
        self._entity.decided_at = utc_now()

        return new_state

    def complete_download(self) -> CRStatus:
        """Mark certificate as downloaded.

        Returns:
            New state (COMPLETED)

        Raises:
            InvalidTransitionError: If not in ISSUED state
        """
        return self.transition(CREvent.DOWNLOAD_COMPLETED)

    def cancel(self) -> CRStatus:
        """Cancel the request.

        Returns:
            New state (CANCELLED)

        Raises:
            InvalidTransitionError: If in terminal state
        """
        return self.transition(CREvent.CANCELLATION_REQUESTED)
