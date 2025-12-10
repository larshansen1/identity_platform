from enum import StrEnum


class SubjectType(StrEnum):
    MACHINE_CLIENT = "machine_client"
    HUMAN_USER = "human_user"


class MachineClientStatus(StrEnum):
    """All possible states for MachineClient entity."""

    PENDING_CERTIFICATE = "pending_certificate"
    ACTIVE = "active"
    REVOKED = "revoked"  # Terminal state


class MachineClientEvent(StrEnum):
    """All possible events that trigger MachineClient transitions."""

    CERTIFICATE_INSTALLED = "certificate_installed"
    REVOCATION_REQUESTED = "revocation_requested"


class CertificateRequestStatus(StrEnum):
    """All possible states for CertificateRequest entity."""

    PENDING = "pending"
    ISSUED = "issued"
    COMPLETED = "completed"  # Terminal state
    CANCELLED = "cancelled"  # Terminal state


class CertificateRequestEvent(StrEnum):
    """All possible events that trigger CertificateRequest transitions."""

    APPROVED = "approved"
    REJECTED = "rejected"
    DOWNLOAD_COMPLETED = "download_completed"
    CANCELLATION_REQUESTED = "cancellation_requested"


class CertificateRequestType(StrEnum):
    INITIAL = "initial"
    RENEWAL = "renewal"


class AdminRole(StrEnum):
    REQUESTER = "requester"
    APPROVER = "approver"
