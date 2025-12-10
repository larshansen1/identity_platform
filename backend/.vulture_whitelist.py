from backend.src.identity.domain.models import (
    AdminUser,
    CertificateRequest,
    IdentityAuditLog,
    IssuedCertificate,
    MachineClient,
)
from backend.src.identity.domain.states import (
    CertificateRequestStatus,
    CertificateRequestType,
    MachineClientStatus,
)
from backend.src.main import health_check
from backend.src.shared.config import Settings
from backend.src.shared.database import get_db, get_db_context

# Pydantic Settings
Settings.model_config
Settings.APP_ENV
Settings.SECRET_KEY
Settings.BOOTSTRAP_ADMIN_EMAIL
Settings.BOOTSTRAP_ADMIN_NAME
Settings.BOOTSTRAP_ADMIN_ROLES

# Domain Models (Attributes used by SQLAlchemy/Alembic or will be used in API)
AdminUser.user_id
AdminUser.email
AdminUser.name
AdminUser.api_key_hash
AdminUser.created_at
AdminUser.owned_clients
AdminUser.requested_certs
AdminUser.approved_certs
AdminUser.has_role

MachineClient.subject_id
MachineClient.description
MachineClient.certificate_thumbprint
MachineClient.certificate_serial
MachineClient.certificate_not_before
MachineClient.owner
MachineClient.certificate_requests
MachineClient.issued_certificates
MachineClient.is_expired
MachineClient.install_certificate
MachineClient.revoke

CertificateRequest.request_id
CertificateRequest.client_id
CertificateRequest.request_type
CertificateRequest.rejection_reason
CertificateRequest.certificate_pem
CertificateRequest.private_key_pem_encrypted
CertificateRequest.created_at
CertificateRequest.decided_at
CertificateRequest.expires_at
CertificateRequest.download_expires_at
CertificateRequest.client
CertificateRequest.requester
CertificateRequest.approver
CertificateRequest.approve
CertificateRequest.reject
CertificateRequest.complete_download
CertificateRequest.cancel

IssuedCertificate.certificate_id
IssuedCertificate.client_id
IssuedCertificate.serial_number
IssuedCertificate.issued_at
IssuedCertificate.revoked_at
IssuedCertificate.revocation_reason
IssuedCertificate.client

IdentityAuditLog.log_id
IdentityAuditLog.timestamp
IdentityAuditLog.event_type
IdentityAuditLog.actor_type
IdentityAuditLog.actor_id
IdentityAuditLog.resource_type
IdentityAuditLog.resource_id
IdentityAuditLog.action
IdentityAuditLog.details
IdentityAuditLog.ip_address
IdentityAuditLog.user_agent

# Enums
MachineClientStatus.INITIAL
MachineClientStatus.RENEWAL
CertificateRequestStatus.REQUESTER
CertificateRequestStatus.APPROVER
CertificateRequestType

# FastAPI
health_check

# Database Dependency
get_db
get_db_context
