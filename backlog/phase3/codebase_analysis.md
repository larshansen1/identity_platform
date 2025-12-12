# Phase 3: Certificate Authority - Codebase Analysis

## Overview

**Phase 3** of the Identity Platform implementation focuses on the **Identity Module - Certificate Authority**. This document provides a thorough analysis of the existing codebase relevant to Phase 3 implementation.

### Phase 3 Scope (from Requirements)

According to `m2m-idp-requirements-v2.md` (lines 1677-1705), Phase 3 includes:

```
src/identity/
├── api/
│   ├── approvals.py      # NEW
│   └── internal.py       # NEW - ValidateCertificate
├── services/
│   ├── approval_service.py    # NEW
│   └── certificate_service.py # NEW
└── ca/                   # NEW - CA operations, crypto
```

**Exit Criteria:**
- [ ] Full approval workflow works
- [ ] CA generates valid X.509 certificates
- [ ] Internal validation API works
- [ ] Self-approval blocked (INV-06)
- [ ] Unit tests for CA operations and approval workflow
- [ ] Metrics emitted: `identity_certificates_generated_total`, `identity_certificate_validations_total`
- [ ] Structured logs for certificate lifecycle events

---

## Current Implementation Status

### ✅ Already Implemented (Phase 1-2)

| Component | Location | Status |
|-----------|----------|--------|
| Domain Models | `src/identity/domain/models.py` | Complete |
| State Machines | `src/identity/domain/state_machines.py` | Complete |
| States/Enums | `src/identity/domain/states.py` | Complete |
| Client Management API | `src/identity/api/clients.py` | Complete |
| API Authentication | `src/identity/api/auth.py` | Complete |
| Client Service | `src/identity/services/client_service.py` | Complete |
| Bootstrap Service | `src/identity/services/bootstrap.py` | Complete |
| Repositories | `src/identity/repository/repositories.py` | Complete |
| Database Migrations | `migrations/versions/` | Complete |
| Shared Infrastructure | `src/shared/` | Complete |

### 🚧 To Be Implemented (Phase 3)

| Component | Location | Description |
|-----------|----------|-------------|
| Approvals API | `src/identity/api/approvals.py` | APPROVER role endpoints |
| Internal API | `src/identity/api/internal.py` | ValidateCertificate endpoint |
| Approval Service | `src/identity/services/approval_service.py` | Approval workflow logic |
| Certificate Service | `src/identity/services/certificate_service.py` | Certificate generation, download |
| CA Module | `src/identity/ca/` | X.509 generation, signing, key management |

---

## Existing Domain Layer Analysis

### Domain Models ([models.py](file:///home/larshansen/Documents/Development/identity_platform/backend/src/identity/domain/models.py))

**Entities relevant to Phase 3:**

#### CertificateRequest (lines 168-261)
```python
class CertificateRequest(Base):
    __tablename__ = "certificate_requests"
    
    request_id: UUID          # Primary key
    client_id: UUID           # FK to MachineClient
    requester_id: UUID        # FK to AdminUser
    request_type: str         # INITIAL | RENEWAL
    status: str               # PENDING | ISSUED | COMPLETED | CANCELLED
    approver_id: UUID | None  # FK to AdminUser (set on approval/rejection)
    rejection_reason: str | None
    certificate_pem: str | None
    private_key_pem_encrypted: str | None
    created_at: datetime
    decided_at: datetime | None
    expires_at: datetime      # Request timeout
    download_expires_at: datetime | None
```

**State Machine Methods Available:**
- `approve(approver_id, cert_pem, key_pem)` → ISSUED
- `reject(approver_id, reason)` → CANCELLED
- `complete_download()` → COMPLETED
- `cancel()` → CANCELLED

#### IssuedCertificate (lines 264-288)
```python
class IssuedCertificate(Base):
    __tablename__ = "issued_certificates"
    
    certificate_id: UUID
    client_id: UUID           # FK to MachineClient
    serial_number: str        # Unique
    thumbprint: str           # SHA-256
    not_before: datetime
    not_after: datetime
    issued_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
```

#### MachineClient Certificate Fields (lines 88-134)
```python
certificate_thumbprint: str | None   # SHA-256 of current cert
certificate_serial: str | None       # Serial number
certificate_not_before: datetime | None
certificate_not_after: datetime | None

# Computed property
@property
def is_expired(self) -> bool:
    return self.certificate_not_after < utc_now()

# State machine method
def install_certificate(thumbprint, serial, not_before, not_after) -> MachineClientStatus
```

### State Machines ([state_machines.py](file:///home/larshansen/Documents/Development/identity_platform/backend/src/identity/domain/state_machines.py))

#### CertificateRequestStateMachine (lines 123-243)

```python
TRANSITIONS = {
    # From PENDING
    (PENDING, APPROVED): ISSUED,
    (PENDING, REJECTED): CANCELLED,
    (PENDING, CANCELLATION_REQUESTED): CANCELLED,
    # From ISSUED
    (ISSUED, DOWNLOAD_COMPLETED): COMPLETED,
    (ISSUED, CANCELLATION_REQUESTED): CANCELLED,
    # COMPLETED and CANCELLED are terminal
}
```

**Key Methods:**
- `approve(approver_id, certificate_pem, private_key_pem_encrypted)` - Sets certificate data, approver, decided_at
- `reject(approver_id, reason)` - Validates reason is non-empty (INV-07)
- `complete_download()` - Marks as downloaded
- `cancel()` - For timeout or cancellation

#### MachineClientStateMachine (lines 42-121)

```python
TRANSITIONS = {
    (PENDING_CERTIFICATE, CERTIFICATE_INSTALLED): ACTIVE,
    (PENDING_CERTIFICATE, REVOCATION_REQUESTED): REVOKED,
    (ACTIVE, CERTIFICATE_INSTALLED): ACTIVE,  # Renewal
    (ACTIVE, REVOCATION_REQUESTED): REVOKED,
}
```

**Key Method:**
- `install_certificate(thumbprint, serial, not_before, not_after)` - Sets all cert fields, transitions to ACTIVE

### States/Enums ([states.py](file:///home/larshansen/Documents/Development/identity_platform/backend/src/identity/domain/states.py))

```python
class CertificateRequestStatus(StrEnum):
    PENDING = "pending"
    ISSUED = "issued"
    COMPLETED = "completed"  # Terminal
    CANCELLED = "cancelled"  # Terminal

class CertificateRequestType(StrEnum):
    INITIAL = "initial"
    RENEWAL = "renewal"

class AdminRole(StrEnum):
    REQUESTER = "requester"
    APPROVER = "approver"
```

---

## Existing API Layer Analysis

### Authentication ([auth.py](file:///home/larshansen/Documents/Development/identity_platform/backend/src/identity/api/auth.py))

**Reusable Components:**
- `get_current_admin()` - Authenticates via X-API-Key header
- `require_role(role: AdminRole)` - Authorization dependency factory

```python
# Usage pattern for Phase 3
@router.get("/api/approvals/pending")
async def list_pending(
    admin: AdminUser = Depends(require_role(AdminRole.APPROVER))
):
    ...
```

### Client API ([clients.py](file:///home/larshansen/Documents/Development/identity_platform/backend/src/identity/api/clients.py))

**Patterns to Follow:**

1. **Request Context Extraction:**
```python
def get_request_context(request: Request) -> RequestContext:
    return RequestContext(
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
```

2. **Service Dependency Injection:**
```python
def get_client_service(db: AsyncSession = Depends(get_db)) -> ClientService:
    return ClientService(db)
```

3. **Error Handling:**
```python
except NotFoundError:
    raise HTTPException(status_code=404, detail="...") from None
except ConflictError as e:
    raise HTTPException(status_code=409, detail=str(e)) from None
```

---

## Existing Service Layer Analysis

### ClientService ([client_service.py](file:///home/larshansen/Documents/Development/identity_platform/backend/src/identity/services/client_service.py))

**Patterns to Follow:**

1. **Service Structure:**
```python
class ClientService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.client_repo = MachineClientRepository(db)
        self.audit_repo = AuditLogRepository(db)
```

2. **Tracing Pattern:**
```python
with tracer.start_as_current_span("ServiceName.method_name") as span:
    span.set_attribute("key", "value")
```

3. **Audit Logging Pattern:**
```python
audit_event = IdentityAuditLog(
    event_type="certificate_request.approved",
    actor_type="admin_user",
    actor_id=approver.user_id,
    resource_type="certificate_request",
    resource_id=request.request_id,
    action="approve",
    details={...},
    ip_address=request_context.ip_address,
    user_agent=request_context.user_agent,
)
await self.audit_repo.create(audit_event)
```

4. **Metric Recording:**
```python
identity_metrics.record_subject_created(SubjectType.MACHINE_CLIENT.value)
```

---

## Repository Layer Analysis

### Existing Repositories ([repositories.py](file:///home/larshansen/Documents/Development/identity_platform/backend/src/identity/repository/repositories.py))

**To be Extended for Phase 3:**

1. **MachineClientRepository** - Add `get_by_id_any_owner()` already exists for approvers
2. **NEW: CertificateRequestRepository** - Needed for:
   - `list_pending(limit, offset)` - For approvers
   - `get_by_id(request_id)` - Without owner restriction for approvers
   - `get_by_id_for_requester(request_id, requester_id)` - For download
   - `create(request)`, `update(request)`
3. **NEW: IssuedCertificateRepository** - Needed for:
   - `create(cert)` - Track issued certs
   - `get_by_serial(serial)` - For validation
   - `get_by_client_id(client_id)` - For certificate history
   - `revoke(cert_id, reason)` - Set revoked_at

---

## Database Schema Analysis

### Relevant Tables (from [817c8fe04b7c_initial_migration.py](file:///home/larshansen/Documents/Development/identity_platform/backend/migrations/versions/817c8fe04b7c_initial_migration.py))

All tables for Phase 3 are already created:

```sql
-- certificate_requests table
CREATE TABLE certificate_requests (
    request_id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES machine_clients ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES admin_users,
    request_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    approver_id UUID REFERENCES admin_users,
    rejection_reason TEXT,
    certificate_pem TEXT,
    private_key_pem_encrypted TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    download_expires_at TIMESTAMPTZ
);

-- Partial unique index for INV-05
CREATE UNIQUE INDEX idx_one_pending_per_client 
    ON certificate_requests(client_id) 
    WHERE status = 'pending';

-- issued_certificates table
CREATE TABLE issued_certificates (
    certificate_id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES machine_clients,
    serial_number VARCHAR(64) UNIQUE NOT NULL,
    thumbprint VARCHAR(64) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);
```

---

## Invariants to Enforce in Phase 3

| ID | Rule | Enforcement Location |
|----|------|---------------------|
| INV-05 | One PENDING request per MachineClient | DB partial unique index (exists) |
| INV-06 | Approver cannot approve own clients | `approval_service.approve()` |
| INV-07 | Rejection requires reason | `CertificateRequestStateMachine.reject()` (exists) |
| INV-08 | COMPLETED is terminal | State machine (exists) |
| INV-09 | CANCELLED is terminal | State machine (exists) |
| INV-10 | All certs signed by CA | `certificate_service.generate()` |
| INV-11 | Cert validity ≤ 365 days | `certificate_service.generate()` |
| INV-12 | Unique serial numbers | DB unique constraint (exists) |
| INV-15 | CA key encrypted at rest | `ca/key_manager.py` |
| INV-16 | Revoked certs fail validation | `internal.py:ValidateCertificate` |

---

## Required Phase 3 Behaviors (from Requirements)

### API Endpoints

#### Approval API (`/api/approvals`)

| Method | Path | Behavior | Auth |
|--------|------|----------|------|
| GET | `/api/approvals/pending` | ListPendingRequests | APPROVER |
| POST | `/api/approvals/{id}/approve` | ApproveRequest | APPROVER |
| POST | `/api/approvals/{id}/reject` | RejectRequest | APPROVER |

#### Client API Extensions (`/api/clients`)

| Method | Path | Behavior | Auth |
|--------|------|----------|------|
| POST | `/api/clients/{id}/certificate-requests` | CreateCertificateRequest | REQUESTER |
| GET | `/api/clients/{id}/certificate-requests/{rid}` | GetCertificateRequest | REQUESTER |
| GET | `/api/clients/{id}/certificate-requests/{rid}/download` | DownloadCertificate | REQUESTER |

#### Internal API (`/internal/identity`)

| Method | Path | Behavior | Auth |
|--------|------|----------|------|
| POST | `/internal/identity/validate-certificate` | ValidateCertificate | Internal |

---

## New Metrics to Implement

From requirements (lines 1468-1481):

```python
# Certificate request metrics
identity_certificate_requests_created_total = Counter(type=initial|renewal)
identity_certificate_requests_approved_total = Counter()
identity_certificate_requests_rejected_total = Counter()
identity_certificate_requests_cancelled_total = Counter()

# Certificate generation metrics
identity_certificates_generated_total = Counter()
identity_certificates_downloaded_total = Counter()
identity_certificate_generation_duration_seconds = Histogram()

# Validation metrics
identity_certificate_validations_total = Counter(result=valid|invalid)

# CA metrics
identity_ca_key_loaded = Gauge(storage_type=file|env|vault)
identity_ca_certificates_signed_total = Counter()
identity_certificates_revoked_total = Counter(reason)
identity_certificate_revocation_checks_total = Counter(result)
```

---

## CA Key Management Requirements

From requirements (lines 360-387):

### Storage Options

| Option | Config | Use Case |
|--------|--------|----------|
| File | `CA_KEY_PATH=/secrets/ca.key` | Development |
| Environment | `CA_KEY_PEM=<base64>` | Container secrets |
| Vault | `CA_KEY_VAULT_PATH=secret/idp/ca` | Production |

### Key Generation

```
- Algorithm: RSA 4096 or ECDSA P-384 (configurable)
- CA certificate validity: 10 years (self-signed root)
- Generated on first startup if not present
```

### Client Certificate Attributes

```
- Subject: CN=<subject_id>
- Validity: now() to now() + 365 days (max, INV-11)
- Key Usage: Digital Signature, Key Encipherment
- Extended Key Usage: Client Authentication
```

---

## Suggested File Structure for Phase 3

```
src/identity/
├── api/
│   ├── approvals.py           # NEW - Approval endpoints
│   ├── internal.py            # NEW - ValidateCertificate
│   ├── clients.py             # EXTEND - Certificate request endpoints
│   └── schemas.py             # EXTEND - New request/response schemas
├── services/
│   ├── approval_service.py    # NEW - Approval workflow
│   ├── certificate_service.py # NEW - Cert generation, download
│   └── client_service.py      # EXTEND - CreateCertificateRequest
├── ca/
│   ├── __init__.py
│   ├── key_manager.py         # NEW - CA key loading/storage
│   ├── certificate_generator.py # NEW - X.509 generation
│   └── crypto.py              # NEW - Encryption utilities
├── repository/
│   └── repositories.py        # EXTEND - CertificateRequest, IssuedCertificate repos
└── metrics.py                 # EXTEND - New Phase 3 metrics
```

---

## Dependencies Analysis

### Python Packages Needed

The following package is likely needed for X.509 certificate generation:

```
cryptography>=41.0.0  # Already in requirements.txt
```

The `cryptography` library provides:
- `x509.CertificateBuilder` - Certificate generation
- RSA/EC key generation
- PEM encoding/decoding
- Certificate signing

### Existing Dependencies in `requirements.txt`

Key packages already available:
- `argon2-cffi` - Password/API key hashing
- `pydantic` - Request/response validation
- `python-jose` - JWT operations (for AuthZ module)
- `opentelemetry-*` - Observability

---

## Testing Considerations

### Existing Test Structure

```
backend/tests/
├── test_security.py      # API key tests
├── test_state_machines.py # State transition tests
└── ...
```

### Phase 3 Test Cases (from requirements lines 1517-1569)

**Approval Tests:**
- `test_approver_cannot_approve_own_requests` (INV-06)
- `test_approver_cannot_reject_without_reason` (INV-07)
- `test_request_pending_to_issued_on_approve`
- `test_inv05_one_pending_request_per_client`

**CA Tests:**
- `test_ca_key_generated_on_first_startup`
- `test_ca_key_loaded_from_file`
- `test_ca_key_loaded_from_env`
- `test_ca_key_encrypted_at_rest` (INV-15)
- `test_ca_certificate_valid_10_years`
- `test_inv11_cert_validity_max_365_days`

**Validation Tests:**
- `test_revoked_cert_fails_validation` (INV-16)
- `test_revocation_immediate_effect`
- `test_client_delete_revokes_certificate`

---

## Summary

Phase 3 implementation will build upon a solid foundation:

1. **Domain Layer** - Complete with all entities and state machines
2. **Database Schema** - All tables exist with proper constraints
3. **API Patterns** - Authentication, authorization, error handling established
4. **Service Patterns** - Tracing, audit logging, metrics patterns in place
5. **Repository Layer** - Base patterns established, needs extension

**Key Implementation Focus Areas:**
1. CA key management and certificate generation
2. Approval workflow with self-approval prevention
3. Certificate download with client activation
4. Internal validation API for AuthZ module
5. Comprehensive audit logging and metrics
