from enum import StrEnum


class SubjectType(StrEnum):
    MACHINE_CLIENT = "machine_client"
    HUMAN_USER = "human_user"


class MachineClientStatus(StrEnum):
    PENDING_CERTIFICATE = "pending_certificate"
    ACTIVE = "active"
    REVOKED = "revoked"


class CertificateRequestStatus(StrEnum):
    PENDING = "pending"
    ISSUED = "issued"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class CertificateRequestType(StrEnum):
    INITIAL = "initial"
    RENEWAL = "renewal"


class AdminRole(StrEnum):
    REQUESTER = "requester"
    APPROVER = "approver"
