from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from shared.database import Base
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .states import (
    AdminRole,
    CertificateRequestStatus,
    MachineClientStatus,
    SubjectType,
)


def utc_now():
    return datetime.now(timezone.utc)


class AdminUser(Base):
    __tablename__ = "admin_users"

    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    roles: Mapped[List[str]] = mapped_column(
        PG_ARRAY(String), nullable=False, default=[]
    )  # Storing roles as array of strings
    api_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # Relationships
    owned_clients: Mapped[List["MachineClient"]] = relationship(
        "MachineClient", back_populates="owner", foreign_keys="[MachineClient.owner_id]"
    )
    requested_certs: Mapped[List["CertificateRequest"]] = relationship(
        "CertificateRequest",
        back_populates="requester",
        foreign_keys="[CertificateRequest.requester_id]",
    )
    approved_certs: Mapped[List["CertificateRequest"]] = relationship(
        "CertificateRequest",
        back_populates="approver",
        foreign_keys="[CertificateRequest.approver_id]",
    )

    def has_role(self, role: AdminRole) -> bool:
        return role.value in self.roles


class Subject(Base):
    __tablename__ = "subjects"

    subject_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    subject_type: Mapped[str] = mapped_column(String(50), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __mapper_args__ = {"polymorphic_on": "subject_type", "polymorphic_identity": "subject"}


class MachineClient(Subject):
    __tablename__ = "machine_clients"

    subject_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("subjects.subject_id", ondelete="CASCADE"),
        primary_key=True,
    )
    owner_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("admin_users.user_id"), nullable=False
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Client Certificate Auth
    certificate_thumbprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    certificate_serial: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    certificate_not_before: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    certificate_not_after: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __mapper_args__ = {
        "polymorphic_identity": SubjectType.MACHINE_CLIENT.value,
    }

    __table_args__ = (
        CheckConstraint(
            "(certificate_thumbprint IS NULL AND certificate_serial IS NULL AND "
            "certificate_not_before IS NULL AND certificate_not_after IS NULL) OR "
            "(certificate_thumbprint IS NOT NULL AND certificate_serial IS NOT NULL AND "
            "certificate_not_before IS NOT NULL AND certificate_not_after IS NOT NULL)",
            name="check_certificate_fields_all_or_none",
        ),
    )

    # Relationships
    owner: Mapped["AdminUser"] = relationship(
        "AdminUser", back_populates="owned_clients", foreign_keys=[owner_id]
    )
    certificate_requests: Mapped[List["CertificateRequest"]] = relationship(
        "CertificateRequest", back_populates="client"
    )
    issued_certificates: Mapped[List["IssuedCertificate"]] = relationship(
        "IssuedCertificate", back_populates="client"
    )

    @property
    def is_expired(self) -> bool:
        if self.certificate_not_after is None:
            return False
        return self.certificate_not_after < utc_now()

    def install_certificate(
        self, thumbprint: str, serial: str, not_before: datetime, not_after: datetime
    ):
        if self.status == MachineClientStatus.REVOKED:
            raise ValueError("Cannot modify revoked client")

        self.certificate_thumbprint = thumbprint
        self.certificate_serial = serial
        self.certificate_not_before = not_before
        self.certificate_not_after = not_after

        if self.status == MachineClientStatus.PENDING_CERTIFICATE:
            self.status = MachineClientStatus.ACTIVE.value

    def revoke(self):
        self.status = MachineClientStatus.REVOKED.value


class CertificateRequest(Base):
    __tablename__ = "certificate_requests"

    request_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    client_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("machine_clients.subject_id", ondelete="CASCADE"),
        nullable=False,
    )
    requester_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("admin_users.user_id"), nullable=False
    )

    request_type: Mapped[str] = mapped_column(String(20), nullable=False)  # CertificateRequestType
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=CertificateRequestStatus.PENDING.value
    )

    approver_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("admin_users.user_id"), nullable=True
    )
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    certificate_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    private_key_pem_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    download_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "idx_one_pending_per_client",
            "client_id",
            unique=True,
            postgresql_where=(status == "pending"),
        ),
    )

    # Relationships
    client: Mapped["MachineClient"] = relationship(
        "MachineClient", back_populates="certificate_requests"
    )
    requester: Mapped["AdminUser"] = relationship(
        "AdminUser", foreign_keys=[requester_id], back_populates="requested_certs"
    )
    approver: Mapped["AdminUser"] = relationship(
        "AdminUser", foreign_keys=[approver_id], back_populates="approved_certs"
    )

    def approve(self, approver_id: UUID, cert_pem: str, key_pem: str):
        if self.status != CertificateRequestStatus.PENDING:
            raise ValueError(f"Cannot approve request in state {self.status}")

        self.approver_id = approver_id
        self.status = CertificateRequestStatus.ISSUED.value
        self.certificate_pem = cert_pem
        self.private_key_pem_encrypted = key_pem
        self.decided_at = utc_now()

    def reject(self, approver_id: UUID, reason: str):
        if self.status != CertificateRequestStatus.PENDING:
            raise ValueError(f"Cannot reject request in state {self.status}")
        if not reason:
            raise ValueError("Rejection reason is required")

        self.approver_id = approver_id
        self.status = CertificateRequestStatus.CANCELLED.value
        self.rejection_reason = reason
        self.decided_at = utc_now()

    def complete_download(self):
        if self.status != CertificateRequestStatus.ISSUED:
            raise ValueError(f"Cannot complete download in state {self.status}")
        self.status = CertificateRequestStatus.COMPLETED.value

    def cancel(self):
        if self.status in [CertificateRequestStatus.COMPLETED, CertificateRequestStatus.CANCELLED]:
            raise ValueError(f"Cannot cancel request in terminal state {self.status}")
        self.status = CertificateRequestStatus.CANCELLED.value


class IssuedCertificate(Base):
    __tablename__ = "issued_certificates"

    certificate_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    client_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("machine_clients.subject_id"), nullable=False
    )
    serial_number: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    thumbprint: Mapped[str] = mapped_column(String(64), nullable=False)

    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    client: Mapped["MachineClient"] = relationship(
        "MachineClient", back_populates="issued_certificates"
    )


class IdentityAuditLog(Base):
    __tablename__ = "identity_audit_logs"

    log_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(50), nullable=False)
    actor_id: Mapped[Optional[UUID]] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
