# Identity Platform Requirements - Phase 1: Machine Identity & Authentication

## Overview

**Purpose:** Self-service identity platform enabling machine clients to register, obtain certificates, and authenticate via OAuth 2.0 with mTLS/DPoP. This is **Phase 1** of a larger identity platform that will eventually include human identity and access management.

**Platform Vision:**
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Identity Platform                                  │
├───────────────────────────────────┬─────────────────────────────────────────┤
│         Identity Service          │         Authorization Server            │
│         (Who are you?)            │      (Prove it, get token)              │
├───────────────────────────────────┼─────────────────────────────────────────┤
│ ✅ Machine Clients                │ ✅ Token endpoint                       │
│    - Registration                 │ ✅ mTLS + DPoP validation               │
│    - Lifecycle management         │ ✅ JWT issuance                         │
│                                   │ ✅ Discovery (.well-known)              │
│ ✅ Certificate Authority (CA)     │                                         │
│    - Certificate issuance         │ ⏳ OIDC/SAML (human auth)               │
│    - Certificate validation       │ ⏳ Scope resolution                     │
│                                   │ ⏳ Role resolution                      │
│ ✅ Certificate Request Workflow   │                                         │
│    - Approval process             │                                         │
│                                   │                                         │
│ ⏳ Human Users                    │                                         │
│    - Local accounts               │                                         │
│    - Federated SSO                │                                         │
├───────────────────────────────────┴─────────────────────────────────────────┤
│                        Access Management (Future)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ ⏳ Roles, Scopes, Permissions                                                │
│ ⏳ Assignments (subject → role, client → scope)                             │
│ ⏳ Policy evaluation                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✅ = This phase    ⏳ = Future phases                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

**This Phase Delivers:**
- Machine client registration and certificate lifecycle (Identity Service)
- Certificate Authority for client certificates (Identity Service)
- OAuth 2.0 token endpoint with mTLS + DPoP (Authorization Server)
- Foundation abstractions for future human identity and access management

**Future Phases (Not in Scope, But Designed For):**
- Phase 2: Human Identity (local accounts, OIDC federation, SAML)
- Phase 3: Access Management (roles, scopes, permissions, policies)

**Actors (This Phase):** Requester, Approver, Machine Client, Identity Service, Authorization Server, Resource Server

**Actors (Future):** User Administrator, Human User, External Identity Provider (OIDC/SAML)

**Tech stack:**
- Language: Python 3.12 (plain, minimal dependencies)
- Database: PostgreSQL 16
- Deployment: Podman + Podman Compose
- Testing: pytest
- Linting: ruff
- Security: bandit
- Observability: OpenTelemetry SDK (logs, metrics, traces)
  - Phase 1: stdout/JSON (container logs), `/metrics` endpoint
  - Future: OTLP export to external backends (Prometheus, Jaeger, etc.)

Please note - the directory contains app directory. The requirements suggests a better structure (backend / frontend). Use the improved structure. The Makefile and some of the scriptsprovided will have to be adjusted.

**Timeline goal:** 2-3 weeks (5 phases)

---

## Architecture

### Key Architectural Decision: Identity Service Owns CA

**Decision:** The Identity Service owns the Certificate Authority (CA) function.

**Rationale:**
1. **Conceptual alignment:** A certificate answers "who is this?" - that's identity, not authorization
2. **Lifecycle coupling:** Certificate lifecycle is tied to client identity lifecycle
3. **Clear ownership:** Identity Service is source of truth for which credentials are valid
4. **Consistent pattern:** When human users arrive, Identity Service will also own password hashing and federation links

```
Certificate = "This is Machine Client X" (Identity concern)
Token       = "Client X is authenticated, here's proof" (Authorization concern)
```

### Bounded Contexts

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Identity Platform Contexts                            │
├───────────────────────────────────┬─────────────────────────────────────────┤
│      Identity Context             │        Authorization Context            │
│      (This Phase)                 │        (This Phase - partial)           │
├───────────────────────────────────┼─────────────────────────────────────────┤
│                                   │                                         │
│  Subject (abstract)               │  TokenRequest                           │
│  ├─ MachineClient                 │  TokenResponse                          │
│  └─ HumanUser (future)            │  DPoPProof                              │
│                                   │                                         │
│  Credential (abstract)            │  (Future)                               │
│  ├─ Certificate                   │  Scope                                  │
│  ├─ Password (future)             │  Role                                   │
│  └─ FederatedLink (future)        │  Permission                             │
│                                   │  ScopeGrant                             │
│  CertificateRequest               │  RoleAssignment                         │
│  CertificateAuthority  ◄── CA     │                                         │
│                                   │                                         │
│  AdminUser                        │                                         │
│  AuditLog                         │  AuditLog                               │
│                                   │                                         │
└───────────────────────────────────┴─────────────────────────────────────────┘

Communication:
─────────────
Authorization Server ───► Identity Service (validate certificate)
                     ◄─── (validation result)

Identity Service does NOT call Authorization Server
```

### Deployment Strategy: Modular Monolith

For Phase 1, deploy as a single service with strict module boundaries. This enables fast iteration while maintaining clean separation for future service extraction.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Identity Platform (Monolith)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────┐    ┌─────────────────────────────┐        │
│  │     Identity Module         │    │   Authorization Module      │        │
│  ├─────────────────────────────┤    ├─────────────────────────────┤        │
│  │ • Client management API     │    │ • Token endpoint            │        │
│  │ • Approval API              │    │ • Discovery endpoints       │        │
│  │ • Certificate Authority     │◄───│ • Certificate validation    │        │
│  │ • Certificate requests      │    │   (calls Identity)          │        │
│  └─────────────────────────────┘    └─────────────────────────────┘        │
│               │                                   │                         │
│               ▼                                   ▼                         │
│  ┌─────────────────────────────────────────────────────────────────┐       │
│  │                    Shared Infrastructure                         │       │
│  │         (Database, Logging, Metrics, Configuration)              │       │
│  └─────────────────────────────────────────────────────────────────┘       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Module Rules:**
1. `authz` module CAN call `identity` module (via internal interface)
2. `identity` module CANNOT call `authz` module
3. Each module has its own database tables (no cross-module joins)
4. Modules communicate via defined interfaces, not direct repository access
5. Can split into separate services later by extracting modules

### Extension Points (Designed Now, Implemented Later)

| Extension Point | Current Implementation | Future Implementation |
|-----------------|------------------------|----------------------|
| Subject | `MachineClient` only | Add `HumanUser` |
| Credential | `Certificate` only | Add `Password`, `FederatedLink` |
| Authentication | mTLS + DPoP | Add OIDC, SAML |
| Token Claims | `sub`, `client_id`, `cnf` | Add `scope`, `roles` |
| Grant Types | `client_credentials` | Add `authorization_code`, `refresh_token` |
| Scope Resolution | None (binary auth) | Role → Scope mapping |

### Identity Terminology

**Canonical Identifier:** `subject_id` is the single source of truth for identity.

| Term | Definition | Usage |
|------|------------|-------|
| `subject_id` | UUID, globally unique across all subject types | Canonical identity key in DB, tokens, logs |
| `client_id` | API alias for `subject_id` when context is machine clients | OAuth token requests, API parameters |
| `sub` | JWT claim containing `subject_id` | Token claims (RFC 7519) |

**Rules:**
- In database: always `subject_id`
- In APIs: `client_id` is accepted as parameter name for machine clients, internally mapped to `subject_id`
- In tokens: `sub` = `subject_id`, `client_id` = `subject_id` (same value, different claim names for OAuth compatibility)
- In logs/metrics: always `subject_id`

**Future:** When Human Users are added, `user_id` becomes another API alias for `subject_id`. The canonical key remains `subject_id` throughout.

### Internal API Contract (Identity ↔ Authorization)

The Authorization Server calls Identity Service for certificate validation. This is a critical path for all token issuance.

**Endpoint:** `POST /internal/identity/validate-certificate`

**Contract:**

| Aspect | Requirement |
|--------|-------------|
| **Latency** | P99 < 50ms (in-process call for monolith, HTTP for microservices) |
| **Availability** | If Identity is down, token issuance fails (no fallback) |
| **Idempotency** | Safe to retry; read-only operation |

**Error Semantics:**

| Response | Meaning | AuthZ Action |
|----------|---------|--------------|
| `{valid: true, ...}` | Certificate is valid | Issue token |
| `{valid: false, reason: "UNKNOWN_SUBJECT"}` | Subject ID not found | Return `invalid_client` |
| `{valid: false, reason: "THUMBPRINT_MISMATCH"}` | Certificate doesn't match | Return `invalid_client` |
| `{valid: false, reason: "CERTIFICATE_EXPIRED"}` | Cert past expiry | Return `invalid_client` |
| `{valid: false, reason: "SUBJECT_REVOKED"}` | Client is revoked | Return `invalid_client` |
| HTTP 5xx / timeout | Identity Service error | Return `server_error`, log alert |

**Error Categories:**
- **Permanent errors** (no retry): `UNKNOWN_SUBJECT`, `SUBJECT_REVOKED`
- **Correctable errors** (client can fix): `THUMBPRINT_MISMATCH`, `CERTIFICATE_EXPIRED`
- **Transient errors** (retry with backoff): HTTP 5xx, timeout

**Observability Requirements:**
- Trace IDs must propagate from AuthZ request through Identity call
- Logs must correlate by `subject_id` and `jti` (token ID)
- Metric: `identity_internal_api_duration_seconds{endpoint="validate-certificate"}`

### Certificate Lifecycle

**Entity Responsibilities:**
- `MachineClient`: Owns identity lifecycle (PENDING_CERTIFICATE → ACTIVE → REVOKED)
- `CertificateRequest`: Owns approval workflow (PENDING → ISSUED → COMPLETED/CANCELLED)
- `IssuedCertificate`: Owns CA audit trail (issued, revoked_at, serial tracking)

---

## Actors

### Actor: Requester (Human) — This Phase

**Description:** Human administrator who manages machine client identities on behalf of applications/services.

**Can:**
- View list of own machine clients
- View machine client metadata (client ID, certificate thumbprint, expiry, status)
- Create new machine client
- Request certificate for own machine client
- Download approved certificate
- Delete own machine client

**Cannot:**
- View or modify other users' machine clients
- Approve own certificate requests
- Download certificate before approval
- Create certificate request while one is pending
- Modify revoked machine clients
- Access CA private keys
- *(Future: Manage human users - requires User Administrator role)*
- *(Future: Assign roles/scopes - requires User Administrator role)*

**Sends:**
- `CreateMachineClient` → Identity Service
- `CreateCertificateRequest` → Identity Service
- `DownloadCertificate` → Identity Service
- `DeleteMachineClient` → Identity Service

**Receives:**
- `MachineClientCreated` - confirmation with client_id
- `CertificateRequestCreated` - confirmation with request_id
- `CertificateRequestApproved` - notification certificate ready
- `CertificateRequestRejected` - notification with reason
- `CertificateBundle` - certificate + private key + CA cert

---

### Actor: Approver (Human) — This Phase

**Description:** Privileged human administrator who reviews and decides on certificate requests.

**Can:**
- View list of pending certificate requests
- View certificate request details
- Approve certificate requests
- Reject certificate requests with mandatory reason

**Cannot:**
- Approve requests for clients they own (separation of duties)
- Reject without providing reason
- Modify machine clients directly
- Download certificates
- Access CA private keys
- *(Future: Approve human user registrations)*
- *(Future: Approve role assignments)*

**Sends:**
- `ListPendingRequests` → Identity Service
- `ApproveRequest` → Identity Service
- `RejectRequest` → Identity Service

**Receives:**
- `PendingRequestsList` - queue of requests
- `RequestApproved` - confirmation
- `RequestRejected` - confirmation

---

### Actor: Machine Client — This Phase

**Description:** Software application that authenticates to access protected resources.

**Can:**
- Authenticate using client certificate (mTLS) to Authorization Server
- Request access tokens with DPoP proof
- Present access tokens to resource servers
- *(Future: Request specific scopes during token request)*

**Cannot:**
- Authenticate without valid certificate
- Authenticate with expired/revoked credentials
- Use tokens without matching DPoP key
- Access Identity Service APIs directly
- *(Future: Request scopes not granted to this client)*

**Sends:**
- `TokenRequest` → Authorization Server
- `ResourceRequest` → Resource Server

**Receives:**
- `TokenResponse` - access_token, token_type, expires_in
- `TokenError` - error details
- `ResourceResponse` - protected resource data

---

### Actor: Identity Service (System) — This Phase

**Description:** System component that manages identities and acts as Certificate Authority.

**Responsibilities:**
- Machine client registration and lifecycle
- Certificate Authority (CA) operations
- Certificate request approval workflow
- Certificate validation for Authorization Server
- *(Future: Human user registration)*
- *(Future: Password and federation credential management)*

**Can:**
- Create, update, revoke machine clients
- Generate and sign X.509 certificates
- Track certificate validity and thumbprints
- Validate certificates on behalf of Authorization Server

**Cannot:**
- Issue tokens (Authorization Server responsibility)
- Make authorization decisions
- Access Authorization Server internal state

**Owns (Database Tables):**
- `subjects` - abstract identity records
- `machine_clients` - machine-specific attributes
- `certificate_requests` - approval workflow
- `admin_users` - platform administrators
- `issued_certificates` - CA tracking
- `identity_audit_log` - identity events

**Owns (Secrets):**
- CA private key (for signing certificates)

**CA Private Key Management:**

*Initial Provisioning:*
- CA key pair generated on first startup if not present
- Algorithm: RSA 4096 or ECDSA P-384 (configurable)
- CA certificate validity: 10 years (self-signed root)

*Storage Options (configurable):*

| Option | Config | Use Case |
|--------|--------|----------|
| File | `CA_KEY_PATH=/secrets/ca.key` | Development, simple deployments |
| Environment | `CA_KEY_PEM=<base64>` | Container secrets |
| Vault | `CA_KEY_VAULT_PATH=secret/idp/ca` | Production (HashiCorp Vault) |

*Key Rotation:*
- CA rotation is a major operational event (all client certs become untrusted)
- Mitigation: Issue client certs with shorter validity than CA cert
- Rotation procedure documented separately (out of Phase 1 scope)

*Compromise Response:*
- Revoke all issued certificates
- Generate new CA key pair
- Re-issue all active client certificates
- Notify all Resource Servers of new CA certificate

---

### Actor: Authorization Server (System) — This Phase

**Description:** System component that authenticates subjects and issues access tokens.

**Responsibilities:**
- Validate client authentication (mTLS + DPoP)
- Issue JWT access tokens
- Publish discovery metadata (.well-known)
- *(Future: OIDC/SAML authentication flows)*
- *(Future: Scope and role resolution)*

**Can:**
- Validate certificates by calling Identity Service
- Issue signed JWT access tokens
- Publish JWKS for token verification

**Cannot:**
- Issue or revoke certificates (Identity Service responsibility)
- Manage client registrations
- Directly access Identity Service database tables

**Owns (Database Tables):**
- `token_signing_keys` - JWT signing keys
- `authz_audit_log` - authorization events
- *(Future: `scopes`, `roles`, `scope_grants`, `role_assignments`)*

**Owns (Secrets):**
- Token signing private keys (for JWT signatures)

---

### Actor: Resource Server (System) — This Phase

**Description:** Protected API that validates tokens and serves authenticated requests.

**Can:**
- Validate JWT access token signature (using JWKS from Authorization Server)
- Verify token expiration and claims
- Verify DPoP proof binding
- Return protected resources
- *(Future: Check scope claims for authorization)*

**Cannot:**
- Issue tokens
- Modify identities
- Call Identity Service directly

---

### Actor: User Administrator (Human) — Future Phase

**Description:** Privileged user who manages human identities and access assignments.

**Can (Future):**
- Create/disable human user accounts
- Assign roles to subjects (machine or human)
- Grant scopes to machine clients
- Configure federation (OIDC/SAML providers)
- View access audit logs

---

### Actor: Human User — Future Phase

**Description:** Human end-user who authenticates to access resources.

**Can (Future):**
- Authenticate via local credentials
- Authenticate via federated identity (OIDC/SAML)
- Request access tokens
- Access resources based on assigned roles

---

## Entities & States

### Entity: Subject (Abstract) — Extension Point

**Purpose:** Abstract base representing anything that can authenticate and be authorized.

**Owned by:** Identity Service

**Note:** This phase only implements `MachineClient`. The abstraction exists to enable future `HumanUser` extension.

**Key attributes (shared by all subjects):**
- `subject_id`: UUID - globally unique identifier
- `subject_type`: Enum - MACHINE_CLIENT, HUMAN_USER (future)
- `display_name`: String - human-readable name
- `status`: Enum - lifecycle state
- `created_at`: DateTime
- `updated_at`: DateTime

**Token Claim Mapping:**
- `sub` claim = `subject_id`
- `subject_type` claim = `subject_type`

---

### Entity: MachineClient (extends Subject) — This Phase

**Purpose:** Registered machine identity with certificate binding.

**Owned by:** Identity Service

**Key attributes:**
- (inherited from Subject)
- `owner_id`: UUID - FK to AdminUser who manages this client
- `description`: String - optional description
- `certificate_thumbprint`: String (nullable) - SHA-256 of current certificate
- `certificate_serial`: String (nullable) - certificate serial number
- `certificate_not_before`: DateTime (nullable)
- `certificate_not_after`: DateTime (nullable)

**Has state machine:** Yes

**States:**
- `PENDING_CERTIFICATE`: Registered, awaiting first certificate
- `ACTIVE`: Valid certificate installed, can authenticate
- `REVOKED`: Permanently disabled (terminal)

**Computed Properties (not persisted states):**
- `is_expiring`: `certificate_not_after ≤ now() + 30 days` — triggers renewal warning
- `is_expired`: `certificate_not_after < now()` — blocks authentication

**State Diagram:**
```
┌─────────────────────┐    cert_installed    ┌────────┐
│ PENDING_CERTIFICATE │ ──────────────────►  │ ACTIVE │ ◄──┐
└─────────────────────┘                      └────────┘    │
         │                                        │        │ cert_renewed
         │ revoke                                 │        │
         ▼                                        ▼        │
    ┌─────────┐       revoke                 (computed)    │
    │ REVOKED │  ◄────────────────────────   is_expired ───┘
    └─────────┘                              (can renew)
```

**Transitions:**

| From | To | Trigger | Actor | Conditions |
|------|----|---------|-------|------------|
| PENDING_CERTIFICATE | ACTIVE | cert_installed | Identity Service | Certificate downloaded |
| PENDING_CERTIFICATE | REVOKED | revoke | Requester | Owner deletes |
| ACTIVE | ACTIVE | cert_renewed | Identity Service | New certificate installed |
| ACTIVE | REVOKED | revoke | Requester | Owner deletes |

**Runtime Checks (not state transitions):**
- Authentication blocked if `is_expired = true`
- Renewal warning shown if `is_expiring = true`

> **Note:** Expiry does not modify state; it only affects runtime authorization. A MachineClient remains `ACTIVE` even with an expired certificate—it simply cannot authenticate until renewed.

**Terminal states:** REVOKED

---

### Entity: CertificateRequest — This Phase

**Purpose:** Workflow item for certificate issuance approval.

**Owned by:** Identity Service

**Key attributes:**
- `request_id`: UUID
- `client_id`: UUID - FK to MachineClient
- `requester_id`: UUID - FK to AdminUser
- `request_type`: Enum - INITIAL, RENEWAL
- `status`: Enum - PENDING, ISSUED, COMPLETED, CANCELLED
- `approver_id`: UUID (nullable)
- `rejection_reason`: String (nullable)
- `certificate_pem`: Text (nullable) - generated certificate
- `private_key_pem_encrypted`: Text (nullable) - encrypted private key
- `created_at`: DateTime
- `decided_at`: DateTime (nullable)
- `expires_at`: DateTime - request timeout
- `download_expires_at`: DateTime (nullable) - download window

**Has state machine:** Yes

**States:**
- `PENDING`: Awaiting approver decision
- `ISSUED`: Certificate ready for download (approval + generation combined)
- `COMPLETED`: Certificate retrieved (terminal)
- `CANCELLED`: Request denied or timed out (terminal)

**Design Decision:** The `APPROVED` state is eliminated — certificate generation happens synchronously on approval. If generation fails, the request stays `PENDING` for retry.

**State Diagram:**
```
                    approve + generate
┌─────────┐  ────────────────────────────►  ┌────────┐   download   ┌───────────┐
│ PENDING │                                 │ ISSUED │ ───────────► │ COMPLETED │
└─────────┘                                 └────────┘              └───────────┘
     │                                           │
     │ reject / timeout                          │ timeout
     ▼                                           ▼
┌───────────┐                              ┌───────────┐
│ CANCELLED │ ◄────────────────────────────│ CANCELLED │
└───────────┘                              └───────────┘
```

**Transitions:**

| From | To | Trigger | Actor | Conditions |
|------|----|---------|-------|------------|
| PENDING | ISSUED | approve | Approver | Approver ≠ client owner, cert generation succeeds |
| PENDING | CANCELLED | reject | Approver | Reason provided |
| PENDING | CANCELLED | timeout | Identity Service | Now > expires_at |
| ISSUED | COMPLETED | download | Requester | Requester = client owner |
| ISSUED | CANCELLED | timeout | Identity Service | Now > download_expires_at |

**Terminal states:** COMPLETED, CANCELLED

---

### Entity: IssuedCertificate — This Phase

**Purpose:** Record of certificates issued by the CA for tracking and revocation.

**Owned by:** Identity Service

**Key attributes:**
- `certificate_id`: UUID
- `client_id`: UUID - FK to MachineClient
- `serial_number`: String - certificate serial (unique)
- `thumbprint`: String - SHA-256 thumbprint
- `not_before`: DateTime
- `not_after`: DateTime
- `issued_at`: DateTime
- `revoked_at`: DateTime (nullable)
- `revocation_reason`: String (nullable)

### Certificate Revocation

**Mechanism:** Database-backed revocation checking (no CRL/OCSP in Phase 1)

**How it works:**
1. When client is revoked → `issued_certificates.revoked_at` set to now()
2. `ValidateCertificate` checks `revoked_at IS NULL` for the serial number
3. Revocation is immediate (no propagation delay)

**Revocation Sources:**
- Client deletion by Requester → automatic certificate revocation
- Future: Manual revocation by Approver (Phase 2)

**Resource Server Consideration:**
- Resource Servers validate tokens, not certificates
- Token expiry (≤1 hour) limits exposure window after revocation
- For immediate revocation effect: configure short token lifetime

**Future Enhancement (Post-Phase 1):**
- OCSP responder endpoint for direct certificate status queries
- CRL publication for offline validation scenarios

---

### Entity: AdminUser — This Phase

**Purpose:** Human administrator who manages machine clients (Requester/Approver roles).

**Owned by:** Identity Service

**Key attributes:**
- `user_id`: UUID
- `email`: String - unique
- `name`: String
- `roles`: Set[Enum] - REQUESTER, APPROVER
- `api_key_hash`: String
- `created_at`: DateTime

---

### Entity: TokenSigningKey — This Phase

**Purpose:** RSA/EC key pair used to sign JWT access tokens.

**Owned by:** Authorization Server

**Key attributes:**
- `key_id`: String - unique key identifier (used in JWT `kid` header)
- `algorithm`: Enum - RS256, ES256
- `public_key_pem`: Text - public key for JWKS
- `private_key_pem_encrypted`: Text - encrypted private key
- `created_at`: DateTime
- `expires_at`: DateTime (nullable) - for key rotation
- `is_active`: Boolean - currently used for signing

---

### Entity: AccessToken (Conceptual) — This Phase

**Purpose:** OAuth 2.0 access token claims structure.

**Owned by:** Authorization Server (issued, not persisted)

**Current Claims (This Phase):**
```json
{
  "iss": "https://auth.example.com",
  "sub": "<subject_id>",
  "client_id": "<client_id>",
  "subject_type": "machine_client",
  "iat": 1234567890,
  "exp": 1234571490,
  "jti": "<unique_token_id>",
  "cnf": {
    "jkt": "<dpop_thumbprint>"
  }
}
```

**Future Claims (Access Management Phase):**
```json
{
  "...current claims...",
  "scope": "read:orders write:orders",
  "roles": ["order-service", "inventory-reader"]
}
```

---

### Entity: HumanUser (extends Subject) — Future Phase

**Purpose:** Human identity that can authenticate via local credentials or federation.

**Owned by:** Identity Service (future)

**Lifecycle Note:** HumanUser lifecycle states will be defined separately (e.g., PENDING_VERIFICATION, ACTIVE, LOCKED, DISABLED) and are not constrained by MachineClient states. The only shared abstraction is the `Subject` base with `subject_id`.

---

### Entity: Role, Scope, ScopeGrant, RoleAssignment — Future Phase

**Owned by:** Authorization Server (future)

**Scope/Role Relationship:** Scopes are the unit of authorization (e.g., `read:orders`). Roles are groupings of scopes (e.g., `order-service` role grants multiple scopes). Tokens will contain scopes, not roles—role resolution happens at token issuance time.

---

## Invariants

### Identity Service Invariants — This Phase

| ID | Rule | Scope | Enforcement |
|----|------|-------|-------------|
| INV-01 | MachineClient.subject_id must be globally unique | MachineClient | Hard block (DB) |
| INV-02 | MachineClient must have exactly one owner | MachineClient | Hard block (NOT NULL FK) |
| INV-03 | certificate_not_after must be set when certificate_thumbprint is set | MachineClient | Hard block (DB CHECK) |
| INV-04 | REVOKED clients cannot transition to any other state | MachineClient | Hard block (state machine) |
| INV-05 | Only one PENDING request per MachineClient at a time | CertificateRequest | Hard block (DB partial unique) |
| INV-06 | Approver cannot approve requests for clients they own | CertificateRequest | Hard block (app logic) |
| INV-07 | rejection_reason must be non-empty when status = CANCELLED and was rejected | CertificateRequest | Hard block (app logic) |
| INV-08 | certificate_pem must be set when status ∈ {ISSUED, COMPLETED} | CertificateRequest | Hard block (app logic) |
| INV-09 | Terminal states (COMPLETED, CANCELLED) cannot transition | CertificateRequest | Hard block (state machine) |
| INV-10 | All certificates signed by platform CA | Certificate | Automatic (CA signs) |
| INV-11 | Certificate validity ≤ 365 days | Certificate | Hard block (generation) |
| INV-12 | Certificate serial numbers must be unique | IssuedCertificate | Hard block (DB unique) |
| INV-13 | Requester can only access own MachineClients | Authorization | Hard block (app logic) |
| INV-14 | AuditLog entries immutable (no UPDATE/DELETE) | AuditLog | Hard block (DB permissions) |
| INV-15 | CA private key must be encrypted at rest | CA | Hard block (startup check) |
| INV-16 | Revoked certificates must fail validation immediately | IssuedCertificate | Hard block (ValidateCertificate) |
| INV-17 | At least one admin with APPROVER role must exist | AdminUser | Soft block (warn on last-admin delete) |

### Authorization Server Invariants — This Phase

| ID | Rule | Scope | Enforcement |
|----|------|-------|-------------|
| INV-20 | Only ACTIVE clients with non-expired certificates can receive tokens | Token endpoint | Hard block |
| INV-21 | Access token expiry must be ≤ 1 hour from issuance | Token | Hard block (generation) |
| INV-22 | Access token must include DPoP binding (cnf.jkt) | Token | Hard block (generation) |
| INV-23 | Token must be signed by active signing key | Token | Automatic |
| INV-24 | All API requests must be authenticated | All APIs | Hard block |

### Cross-Module Invariants — This Phase

| ID | Rule | Scope | Enforcement |
|----|------|-------|---------|
| INV-30 | AuthZ Server must validate certificates via Identity Service | Token endpoint | Hard block (architecture) |
| INV-31 | AuthZ Server cannot directly access Identity database tables | Architecture | Code review / module boundaries |

**INV-31 Rationale:** This ensures Identity remains the single authority on credential validity, enabling central auditing, consistent revocation semantics, and clean module separation when splitting into microservices.

---

## Behaviors

### Identity Service Behaviors — Machine Client Management

#### Behavior: CreateMachineClient

**Actor:** Requester
**Module:** Identity

**Input:**
- `display_name`: String (required, 3-100 chars)
- `description`: String (optional, max 500 chars)

**Preconditions:**
- User authenticated with REQUESTER role

**State changes:**
- Creates: Subject record with subject_type = MACHINE_CLIENT
- Creates: MachineClient record in PENDING_CERTIFICATE state
- Sets: owner_id = current_user.user_id

**Output:**
- Success: `{subject_id, display_name, status: "created", created_at}`
- UNAUTHORIZED: Not authenticated
- FORBIDDEN: Lacks REQUESTER role
- BAD_REQUEST: Validation failed

**Side effects:**
- AuditLog: `machine_client.created`
- Metric: `identity_subjects_created_total{type="machine_client"}` +1
- Log: INFO `subject_created {subject_id, type, owner_id}`

---

#### Behavior: ListMachineClients

**Actor:** Requester
**Module:** Identity

**Input:**
- `status`: Enum (optional) - filter by status
- `limit`: Integer (optional, default 20, max 100)
- `offset`: Integer (optional, default 0)

**Preconditions:**
- User authenticated with REQUESTER role

**State changes:** None

**Output:**
- Success: `{items: [{subject_id, display_name, status, certificate_not_after}], total}`

**Side effects:**
- Log: DEBUG `subjects_listed {owner_id, type, count}`

---

#### Behavior: GetMachineClient

**Actor:** Requester
**Module:** Identity

**Input:**
- `subject_id`: UUID (path parameter)

**Preconditions:**
- User authenticated with REQUESTER role
- MachineClient exists
- MachineClient.owner_id = current_user (INV-13)

**State changes:** None

**Output:**
- Success: `{subject_id, display_name, description, status, certificate_thumbprint, certificate_not_after}`
- NOT_FOUND: Client does not exist
- FORBIDDEN: Not owner

---

#### Behavior: DeleteMachineClient

**Actor:** Requester
**Module:** Identity

**Input:**
- `subject_id`: UUID (path parameter)

**Preconditions:**
- User authenticated with REQUESTER role
- MachineClient exists
- MachineClient.owner_id = current_user
- MachineClient.status ≠ REVOKED (INV-04)

**State changes:**
- MachineClient.status → REVOKED
- Any PENDING CertificateRequest → CANCELLED
- IssuedCertificate.revoked_at = now() (for current cert)

**Output:**
- Success: 204 No Content
- CONFLICT: Already REVOKED

**Side effects:**
- AuditLog: `machine_client.revoked`
- Metric: `identity_subjects_revoked_total{type="machine_client"}` +1
- Log: INFO `subject_revoked {subject_id, type}`

---

### Identity Service Behaviors — Certificate Authority

#### Behavior: CreateCertificateRequest

**Actor:** Requester
**Module:** Identity

**Input:**
- `subject_id`: UUID (path parameter)

**Preconditions:**
- User authenticated with REQUESTER role
- MachineClient exists
- MachineClient.owner_id = current_user
- MachineClient.status ≠ REVOKED
- No PENDING request exists for this client (INV-05)

**State changes:**
- Creates: CertificateRequest in PENDING state
- Sets: request_type = INITIAL if no current cert, else RENEWAL
- Sets: expires_at = now() + 7 days

**Output:**
- Success: `{request_id, subject_id, request_type, status, created_at, expires_at}`
- CONFLICT: PENDING request exists
- UNPROCESSABLE: Client is REVOKED

**Side effects:**
- AuditLog: `certificate_request.created`
- Metric: `identity_certificate_requests_created_total{type}` +1
- Log: INFO `certificate_request_created {request_id, subject_id, type}`

---

#### Behavior: ListPendingRequests

**Actor:** Approver
**Module:** Identity

**Input:**
- `limit`: Integer (optional, default 20, max 100)
- `offset`: Integer (optional, default 0)

**Preconditions:**
- User authenticated with APPROVER role

**State changes:** None

**Output:**
- Success: `{items: [{request_id, subject_id, client_display_name, owner_email, request_type, created_at}], total}`

---

#### Behavior: ApproveRequest

**Actor:** Approver
**Module:** Identity

**Input:**
- `request_id`: UUID (path parameter)

**Preconditions:**
- User authenticated with APPROVER role
- CertificateRequest exists
- CertificateRequest.status = PENDING
- MachineClient.owner_id ≠ current_user (INV-06)

**State changes:**
- Generates certificate synchronously (see GenerateCertificate)
- CertificateRequest.status → ISSUED (on success)
- CertificateRequest.status remains PENDING (on generation failure, for retry)
- CertificateRequest.approver_id = current_user
- CertificateRequest.decided_at = now()

**Output:**
- Success: `{request_id, status: "issued", decided_at}`
- FORBIDDEN: Self-approval attempted
- CONFLICT: Status ≠ PENDING
- INTERNAL_ERROR: Certificate generation failed (stays PENDING)

**Side effects:**
- AuditLog: `certificate_request.approved`
- Metric: `identity_certificate_requests_approved_total` +1
- Log: INFO `certificate_request_approved {request_id, approver_id}`

---

#### Behavior: RejectRequest

**Actor:** Approver
**Module:** Identity

**Input:**
- `request_id`: UUID (path parameter)
- `reason`: String (required, 10-500 chars)

**Preconditions:**
- User authenticated with APPROVER role
- CertificateRequest exists
- CertificateRequest.status = PENDING
- reason is non-empty (INV-07)

**State changes:**
- CertificateRequest.status → CANCELLED
- CertificateRequest.approver_id = current_user
- CertificateRequest.rejection_reason = reason
- CertificateRequest.decided_at = now()

**Output:**
- Success: `{request_id, status: "cancelled", rejection_reason, decided_at}`
- BAD_REQUEST: Reason empty

**Side effects:**
- AuditLog: `certificate_request.rejected`
- Metric: `identity_certificate_requests_rejected_total` +1
- Log: INFO `certificate_request_rejected {request_id, approver_id, reason}`

---

#### Behavior: GenerateCertificate (Internal)

**Actor:** Identity Service (called by ApproveRequest)
**Module:** Identity (CA subsystem)

**Note:** This is an internal operation invoked synchronously during approval, not a separate API.

**Input:**
- `request_id`: UUID

**Preconditions:**
- CertificateRequest.status = PENDING (called during approval)
- CA private key available

**State changes:**
- Generates: X.509 certificate signed by CA
- Generates: RSA 2048 private key for client
- CertificateRequest.status → ISSUED
- CertificateRequest.certificate_pem = generated cert
- CertificateRequest.private_key_pem_encrypted = encrypted key
- CertificateRequest.download_expires_at = now() + 24 hours
- Creates: IssuedCertificate record

**Certificate attributes:**
- Subject: CN=<subject_id>
- Validity: now() to now() + 365 days (max, INV-11)
- Key Usage: Digital Signature, Key Encipherment
- Extended Key Usage: Client Authentication

**Output:**
- Success: Internal completion, approval proceeds
- Error: Raises exception, approval fails, request stays PENDING

**Side effects:**
- AuditLog: `certificate.generated`
- Metric: `identity_certificates_generated_total` +1
- Metric: `identity_certificate_generation_duration_seconds` histogram
- Log: INFO `certificate_generated {request_id, subject_id, serial, not_after}`

---

#### Behavior: DownloadCertificate

**Actor:** Requester
**Module:** Identity

**Input:**
- `request_id`: UUID (path parameter)

**Preconditions:**
- User authenticated with REQUESTER role
- CertificateRequest exists
- CertificateRequest.requester_id = current_user
- CertificateRequest.status = ISSUED
- now() ≤ download_expires_at

**State changes:**
- CertificateRequest.status → COMPLETED
- MachineClient.certificate_thumbprint = computed thumbprint
- MachineClient.certificate_serial = from cert
- MachineClient.certificate_not_before = from cert
- MachineClient.certificate_not_after = from cert
- MachineClient.status → ACTIVE (if was PENDING_CERTIFICATE)

**Output:**
- Success: `{certificate_pem, private_key_pem, ca_certificate_pem, subject_id}`
- CONFLICT: Status ≠ ISSUED
- GONE: Download window expired

**Side effects:**
- AuditLog: `certificate.downloaded`
- Metric: `identity_certificates_downloaded_total` +1
- Log: INFO `certificate_downloaded {request_id, subject_id}`

---

#### Behavior: ValidateCertificate (Internal API)

**Actor:** Authorization Server (internal call)
**Module:** Identity

**Input:**
- `subject_id`: UUID
- `certificate_thumbprint`: String

**Preconditions:** None (internal API, but requires internal authentication)

**State changes:** None

**Output:**
- Valid: `{valid: true, subject_id, subject_type, status}`
- Invalid: `{valid: false, reason: "..."}`

**Validation checks:**
1. MachineClient exists with subject_id
2. MachineClient.certificate_thumbprint matches input
3. MachineClient.status = ACTIVE
4. MachineClient.certificate_not_after > now() (expiry is a runtime check, not a state)
5. Certificate not in revocation list

**Side effects:**
- Metric: `identity_certificate_validations_total{result=valid|invalid}` +1
- Log: DEBUG `certificate_validated {subject_id, result}`

---

### Authorization Server Behaviors — Token Issuance

#### Behavior: RequestAccessToken

**Actor:** Machine Client
**Module:** Authorization

**Input:**
- `grant_type`: String = "client_credentials"
- `client_id`: UUID (form parameter)
- Client certificate via mTLS
- `DPoP` header: JWT proof of possession
- `scope`: String (optional) — **Extension Point for Future**

**Preconditions:**
- mTLS connection established
- DPoP proof is valid JWT with correct htm/htu

**Processing:**
1. Extract certificate thumbprint from mTLS
2. **Call Identity Service: `ValidateCertificate(client_id, thumbprint)`**
3. If invalid → return error
4. Validate DPoP proof
5. Generate access token

**Future Processing (Access Management Phase):**
- Parse requested scopes
- Resolve granted scopes for this client
- Include only intersection in token

**State changes:** None (tokens are stateless)

**Output:**
- Success: `{access_token, token_type: "DPoP", expires_in: 3600}`
- INVALID_CLIENT: Certificate validation failed
- INVALID_GRANT: Client not ACTIVE/EXPIRING
- INVALID_DPOP_PROOF: DPoP validation failed
- USE_DPOP_NONCE: Nonce required (400 with new nonce)

**Token Claims:**
```json
{
  "iss": "<issuer_url>",
  "sub": "<subject_id>",
  "client_id": "<subject_id>",
  "subject_type": "machine_client",
  "iat": <issued_at>,
  "exp": <expires_at>,
  "jti": "<unique_id>",
  "cnf": {"jkt": "<dpop_thumbprint>"}
}
```

**Side effects:**
- AuditLog: `token.issued` or `token.denied`
- Metric: `authz_tokens_issued_total{subject_type, status}` +1
- Metric: `authz_token_request_duration_seconds` histogram
- Log: INFO `token_issued {subject_id, jti}` or WARN `token_denied {subject_id, reason}`

---

#### Behavior: GetOpenIDConfiguration

**Actor:** Any (public)
**Module:** Authorization

**Output:**
```json
{
  "issuer": "https://auth.example.com",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "token_endpoint_auth_methods_supported": ["tls_client_auth"],
  "grant_types_supported": ["client_credentials"],
  "dpop_signing_alg_values_supported": ["RS256", "ES256"]
}
```

---

#### Behavior: GetJWKS

**Actor:** Any (public)
**Module:** Authorization

**Output:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "<key_id>",
      "use": "sig",
      "alg": "RS256",
      "n": "<modulus>",
      "e": "<exponent>"
    }
  ]
}
```

---

### Background Jobs — Identity Service

#### Behavior: ExpireStaleRequests

**Actor:** Identity Service (scheduled)
**Module:** Identity

**Schedule:** Every hour

**Processing:**
- Find CertificateRequests where status = PENDING AND expires_at < now() → CANCELLED
- Find CertificateRequests where status = ISSUED AND download_expires_at < now() → CANCELLED

**Side effects:**
- AuditLog: `certificate_request.cancelled` for each
- Metric: `identity_certificate_requests_cancelled_total` +count
- Log: INFO `requests_cancelled {count}`

---

> **Note:** The `CheckExpiringCertificates` background job has been removed. Certificate expiry is now a computed property (`is_expiring`, `is_expired`) evaluated at runtime rather than a persisted state transition.

---

## API Contract

### API Structure

| API | Module | Base Path | Auth | Phase |
|-----|--------|-----------|------|-------|
| Client Management API | Identity | `/api/clients` | API Key + REQUESTER | This |
| Approval API | Identity | `/api/approvals` | API Key + APPROVER | This |
| Internal Validation API | Identity | `/internal/identity` | Internal only | This |
| Token API | Authorization | `/oauth` | mTLS | This |
| Discovery API | Authorization | `/.well-known` | Public | This |
| Health API | Shared | `/health` | Public | This |

### API Operations — Identity Service

#### Client Management API

| Method | Path | Behavior | Request | Response |
|--------|------|----------|---------|----------|
| POST | `/api/clients` | CreateMachineClient | `{display_name, description?}` | 201 |
| GET | `/api/clients` | ListMachineClients | `?status=&limit=&offset=` | 200 |
| GET | `/api/clients/{id}` | GetMachineClient | - | 200 |
| DELETE | `/api/clients/{id}` | DeleteMachineClient | - | 204 |
| POST | `/api/clients/{id}/certificate-requests` | CreateCertificateRequest | - | 201 |
| GET | `/api/clients/{id}/certificate-requests/{rid}` | GetCertificateRequest | - | 200 |
| GET | `/api/clients/{id}/certificate-requests/{rid}/download` | DownloadCertificate | - | 200 |

#### Approval API

| Method | Path | Behavior | Request | Response |
|--------|------|----------|---------|----------|
| GET | `/api/approvals/pending` | ListPendingRequests | `?limit=&offset=` | 200 |
| POST | `/api/approvals/{id}/approve` | ApproveRequest | - | 200 |
| POST | `/api/approvals/{id}/reject` | RejectRequest | `{reason}` | 200 |

#### Internal Validation API

| Method | Path | Behavior | Request | Response |
|--------|------|----------|---------|----------|
| POST | `/internal/identity/validate-certificate` | ValidateCertificate | `{subject_id, thumbprint}` | 200 |

### API Operations — Authorization Server

#### Token API

| Method | Path | Behavior | Request | Response |
|--------|------|----------|---------|----------|
| POST | `/oauth/token` | RequestAccessToken | `grant_type=client_credentials&client_id=...` + DPoP header | 200 |

#### Discovery API

| Method | Path | Behavior | Response |
|--------|------|----------|----------|
| GET | `/.well-known/openid-configuration` | GetOpenIDConfiguration | 200 |
| GET | `/.well-known/jwks.json` | GetJWKS | 200 |

### Error Responses

| Condition | HTTP Status | Error Code |
|-----------|-------------|------------|
| Not authenticated | 401 | UNAUTHORIZED |
| Invalid API key | 401 | INVALID_API_KEY |
| Insufficient role | 403 | FORBIDDEN |
| Self-approval | 403 | SELF_APPROVAL_DENIED |
| Not found | 404 | NOT_FOUND |
| Invalid state | 409 | INVALID_STATE |
| Pending request exists | 409 | PENDING_REQUEST_EXISTS |
| Download expired | 410 | DOWNLOAD_EXPIRED |
| Validation error | 422 | VALIDATION_ERROR |
| Invalid certificate | 401 | INVALID_CLIENT |
| Invalid DPoP | 401 | INVALID_DPOP_PROOF |

---

## Database Schema

### Module Ownership

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Database Schema Ownership                            │
├───────────────────────────────────┬─────────────────────────────────────────┤
│     Identity Module Tables        │    Authorization Module Tables          │
├───────────────────────────────────┼─────────────────────────────────────────┤
│ • admin_users                     │ • token_signing_keys                    │
│ • subjects                        │ • authz_audit_log                       │
│ • machine_clients                 │ • (future) scopes                       │
│ • certificate_requests            │ • (future) roles                        │
│ • issued_certificates             │ • (future) scope_grants                 │
│ • identity_audit_log              │ • (future) role_assignments             │
│ • (future) human_users            │                                         │
└───────────────────────────────────┴─────────────────────────────────────────┘

Rule: Authorization module CANNOT directly query Identity module tables.
      Must use internal API (ValidateCertificate).
```

### Identity Module Tables

```sql
-- Admin users (platform administrators)
CREATE TABLE admin_users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    roles TEXT[] NOT NULL DEFAULT '{}',
    api_key_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Abstract subject table (polymorphic base)
CREATE TABLE subjects (
    subject_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type VARCHAR(50) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Machine client specific attributes
CREATE TABLE machine_clients (
    subject_id UUID PRIMARY KEY REFERENCES subjects(subject_id) ON DELETE CASCADE,
    owner_id UUID NOT NULL REFERENCES admin_users(user_id),
    description TEXT,
    certificate_thumbprint VARCHAR(64),
    certificate_serial VARCHAR(64),
    certificate_not_before TIMESTAMPTZ,
    certificate_not_after TIMESTAMPTZ,
    
    CONSTRAINT cert_fields_together CHECK (
        (certificate_thumbprint IS NULL AND certificate_not_after IS NULL) OR
        (certificate_thumbprint IS NOT NULL AND certificate_not_after IS NOT NULL)
    )
);

-- Certificate requests (owned by Identity, CA workflow)
CREATE TABLE certificate_requests (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES machine_clients(subject_id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES admin_users(user_id),
    request_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    approver_id UUID REFERENCES admin_users(user_id),
    rejection_reason TEXT,
    certificate_pem TEXT,
    private_key_pem_encrypted TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    download_expires_at TIMESTAMPTZ
);

-- Partial unique: one pending per client
CREATE UNIQUE INDEX idx_one_pending_per_client 
    ON certificate_requests(client_id) 
    WHERE status = 'pending';

-- Issued certificates (CA tracking)
CREATE TABLE issued_certificates (
    certificate_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id UUID NOT NULL REFERENCES machine_clients(subject_id),
    serial_number VARCHAR(64) UNIQUE NOT NULL,
    thumbprint VARCHAR(64) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

-- Identity audit log
CREATE TABLE identity_audit_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    actor_type VARCHAR(50) NOT NULL,
    actor_id UUID,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID NOT NULL,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT
);

REVOKE UPDATE, DELETE ON identity_audit_log FROM PUBLIC;
```

### Authorization Module Tables

```sql
-- Token signing keys (owned by AuthZ)
CREATE TABLE token_signing_keys (
    key_id VARCHAR(64) PRIMARY KEY,
    algorithm VARCHAR(10) NOT NULL,
    public_key_pem TEXT NOT NULL,
    private_key_pem_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Authorization audit log
CREATE TABLE authz_audit_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    actor_type VARCHAR(50) NOT NULL,
    actor_id UUID,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT
);

REVOKE UPDATE, DELETE ON authz_audit_log FROM PUBLIC;
```

---

## Observability

### Metrics — Identity Module

| Name | Type | Description | Labels |
|------|------|-------------|--------|
| `identity_http_requests_total` | Counter | HTTP requests | `method`, `path`, `status` |
| `identity_http_request_duration_seconds` | Histogram | Latency | `method`, `path` |
| `identity_subjects_total` | Gauge | Current subjects | `type`, `status` |
| `identity_subjects_created_total` | Counter | Created | `type` |
| `identity_subjects_revoked_total` | Counter | Revoked | `type` |
| `identity_certificate_requests_total` | Gauge | Current requests | `status` |
| `identity_certificate_requests_created_total` | Counter | Created | `type` |
| `identity_certificate_requests_approved_total` | Counter | Approved | - |
| `identity_certificate_requests_rejected_total` | Counter | Rejected | - |
| `identity_certificate_requests_expired_total` | Counter | Expired | - |
| `identity_certificates_generated_total` | Counter | Generated | - |
| `identity_certificates_downloaded_total` | Counter | Downloaded | - |
| `identity_certificate_generation_duration_seconds` | Histogram | CA time | - |
| `identity_certificate_validations_total` | Counter | Validations | `result` |
| `identity_ca_key_loaded` | Gauge | CA key loaded (1=yes, 0=no) | `storage_type` |
| `identity_ca_certificates_signed_total` | Counter | Certs signed by CA | - |
| `identity_certificates_revoked_total` | Counter | Certificates revoked | `reason` |
| `identity_certificate_revocation_checks_total` | Counter | Revocation lookups | `result` |
| `identity_bootstrap_completed` | Gauge | Bootstrap ran (1=yes) | - |
| `identity_admin_users_total` | Gauge | Current admin count | `role` |

### Metrics — Authorization Module

| Name | Type | Description | Labels |
|------|------|-------------|--------|
| `authz_http_requests_total` | Counter | HTTP requests | `method`, `path`, `status` |
| `authz_http_request_duration_seconds` | Histogram | Latency | `method`, `path` |
| `authz_tokens_issued_total` | Counter | Tokens issued | `subject_type`, `status` |
| `authz_token_request_duration_seconds` | Histogram | Token latency | - |

### Log Events

| Event | Level | Module | Fields |
|-------|-------|--------|--------|
| `subject_created` | INFO | Identity | `subject_id`, `type`, `owner_id` |
| `subject_revoked` | INFO | Identity | `subject_id`, `type` |
| `certificate_request_created` | INFO | Identity | `request_id`, `subject_id`, `type` |
| `certificate_request_approved` | INFO | Identity | `request_id`, `approver_id` |
| `certificate_request_rejected` | INFO | Identity | `request_id`, `reason` |
| `certificate_generated` | INFO | Identity | `request_id`, `serial`, `not_after` |
| `certificate_downloaded` | INFO | Identity | `request_id`, `subject_id` |
| `certificate_validated` | DEBUG | Identity | `subject_id`, `result` |
| `token_issued` | INFO | AuthZ | `subject_id`, `jti` |
| `token_denied` | WARN | AuthZ | `subject_id`, `reason` |
| `ca_key_loaded` | INFO | Identity/CA | `storage_type`, `algorithm`, `ca_cert_expires` |
| `ca_key_load_failed` | ERROR | Identity/CA | `storage_type`, `error` |
| `certificate_revoked` | INFO | Identity | `certificate_id`, `serial`, `reason` |
| `revocation_check` | DEBUG | Identity | `serial`, `revoked` |
| `bootstrap_started` | INFO | Identity | - |
| `bootstrap_admin_created` | INFO | Identity | `email`, `roles` |
| `bootstrap_skipped` | DEBUG | Identity | `reason` |

---

## Test Cases

### Authorization Tests
- `test_requester_cannot_view_other_users_clients`
- `test_requester_cannot_approve_requests`
- `test_approver_cannot_approve_own_requests`
- `test_approver_cannot_reject_without_reason`
- `test_client_cannot_get_token_without_certificate`
- `test_client_cannot_get_token_with_revoked_credential`
- `test_authz_module_cannot_directly_query_identity_tables`

### State Transition Tests
- `test_machine_client_pending_certificate_to_active_on_cert_installed`
- `test_machine_client_cannot_revoked_to_any_state`
- `test_request_pending_to_issued_on_approve`
- `test_request_cannot_completed_to_any`
- `test_expired_cert_blocks_authentication` (computed property)
- `test_expiring_cert_triggers_warning` (computed property)

### Invariant Tests
- `test_inv05_one_pending_request_per_client`
- `test_inv06_approver_not_owner`
- `test_inv10_ca_signs_all_certs`
- `test_inv11_cert_validity_max_365_days`
- `test_inv20_only_active_non_expired_get_tokens`
- `test_inv30_authz_validates_via_identity`
- `test_inv31_authz_no_direct_identity_db_access`

### Integration Tests
- `test_full_flow_create_client_to_token`
- `test_authz_calls_identity_for_validation`
- `test_certificate_renewal_flow`

### CA Key Management Tests
- `test_ca_key_generated_on_first_startup`
- `test_ca_key_loaded_from_file`
- `test_ca_key_loaded_from_env`
- `test_ca_key_encrypted_at_rest` (INV-15)
- `test_ca_certificate_valid_10_years`

### Certificate Revocation Tests
- `test_revoked_cert_fails_validation` (INV-16)
- `test_revocation_immediate_effect`
- `test_client_delete_revokes_certificate`
- `test_revocation_recorded_in_audit_log`

### Bootstrap Tests
- `test_bootstrap_creates_admin_from_env`
- `test_bootstrap_skipped_when_admins_exist`
- `test_bootstrap_admin_has_correct_roles`
- `test_api_key_format_valid`
- `test_api_key_stored_as_argon2_hash`
- `test_last_approver_delete_warning` (INV-17)

---

## Bootstrap & Initial Setup

### First-Run Initialization

On first startup with empty database, the system performs:

1. **Database Migration** - Apply all schema migrations
2. **CA Initialization** - Generate CA key pair if not provided
3. **Admin Bootstrap** - Create initial admin user (see below)
4. **Signing Key Generation** - Create initial JWT signing key

### Initial Admin User

**Option A: Environment Variables (recommended for automation)**
```bash
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_NAME="Platform Admin"
BOOTSTRAP_ADMIN_ROLES=REQUESTER,APPROVER
```
- API key generated and logged at INFO level on first startup
- API key displayed exactly once (not stored in plaintext)

**Option B: CLI Command**
```bash
python -m identity.cli create-admin \
  --email admin@example.com \
  --name "Platform Admin" \
  --roles REQUESTER,APPROVER
```
- Outputs API key to stdout

### API Key Format

- Format: `idp_<random_32_bytes_base64url>` (e.g., `idp_x7Kj9mN2pQ...`)
- Stored as: Argon2id hash in `api_key_hash`
- No expiry in Phase 1 (future: add `api_key_expires_at`)

### Security Considerations

| Risk | Mitigation |
|------|------------|
| Bootstrap key exposure | Key shown once, recommend secure channel |
| Single admin compromise | Create multiple admins, separation of duties |
| No key rotation | Future phase: key rotation API |

---

## Implementation Phases

### Phase 1: Foundation & Core Domain (Est: 3 days)

**Creates:**
```
src/
├── shared/           # Config, DB, logging, metrics
├── identity/
│   └── domain/       # Subject, MachineClient, states
└── authz/
    └── domain/       # TokenSigningKey
migrations/
```

**Implements:**
- Podman Compose with PostgreSQL
- Shared infrastructure
- Entity definitions with validation
- State machines with transition guards
- Database migrations

**Exit criteria:**
- [ ] Domain entities defined with validation
- [ ] State machines enforce transitions
- [ ] Database schema deployed
- [ ] Module boundaries established
- [ ] Unit tests for domain entities and state machines
- [ ] OpenTelemetry SDK configured (logs to stdout/JSON)

---

### Phase 2: Identity Module - Client Management (Est: 3 days)

**Creates:**
```
src/identity/
├── api/              # Client endpoints, middleware
├── services/         # ClientService
└── repository/       # AdminUser, Subject, MachineClient repos
```

**Implements:**
- API key authentication
- CreateMachineClient, ListMachineClients, GetMachineClient, DeleteMachineClient
- Audit logging

**Exit criteria:**
- [ ] Client CRUD works
- [ ] Authorization enforced
- [ ] Audit logging on mutations
- [ ] Unit tests for services and API endpoints
- [ ] Metrics emitted: `identity_subjects_created_total`, `identity_subjects_revoked_total`
- [ ] Structured logs for all client operations

---

### Phase 3: Identity Module - Certificate Authority (Est: 4 days)

**Creates:**
```
src/identity/
├── api/
│   ├── approvals.py
│   └── internal.py   # ValidateCertificate
├── services/
│   ├── approval_service.py
│   └── certificate_service.py
└── ca/               # CA operations, crypto
```

**Implements:**
- Certificate request workflow
- CA certificate generation and signing
- ValidateCertificate internal API
- DownloadCertificate with client activation

**Exit criteria:**
- [ ] Full approval workflow works
- [ ] CA generates valid X.509 certificates
- [ ] Internal validation API works
- [ ] Self-approval blocked (INV-06)
- [ ] Unit tests for CA operations and approval workflow
- [ ] Metrics emitted: `identity_certificates_generated_total`, `identity_certificate_validations_total`
- [ ] Structured logs for certificate lifecycle events

---

### Phase 4: Authorization Module - Token Endpoint (Est: 4 days)

**Creates:**
```
src/authz/
├── api/              # Token, discovery endpoints
├── services/         # TokenService
├── validation/       # DPoP, mTLS
├── jwt/              # Signing, JWKS
└── client/           # IdentityClient (calls Identity)
webapi/               # Sample resource server
```

**Implements:**
- Token endpoint with mTLS + DPoP
- **Identity Service client (calls ValidateCertificate)**
- JWT generation
- Discovery endpoints
- Sample resource server

**Exit criteria:**
- [ ] Token endpoint issues valid JWTs
- [ ] AuthZ calls Identity for certificate validation (INV-30)
- [ ] DPoP validation working
- [ ] Full E2E flow works
- [ ] Unit tests for token generation and validation
- [ ] Integration tests for Identity ↔ AuthZ communication
- [ ] Metrics emitted: `authz_tokens_issued_total`, `authz_token_request_duration_seconds`
- [ ] Structured logs for token issuance and denials

---

### Phase 5: Background Jobs & Production Readiness (Est: 3 days)

**Creates:**
```
src/identity/jobs/    # ExpireRequests, CheckCertificates
docs/                 # OpenAPI, architecture
```

**Implements:**
- Background jobs (ExpireStaleRequests)
- Graceful shutdown
- OpenAPI documentation
- Observability integration (optional: export to external systems)

**Exit criteria:**
- [ ] Background jobs run on schedule
- [ ] All E2E tests pass
- [ ] Test coverage > 80% (cumulative across all phases)
- [ ] All defined metrics exposed on `/metrics` endpoint
- [ ] Health check endpoints operational
- [ ] OpenAPI spec generated and validated

---

## Architecture Decision Records

### ADR-001: Identity Service Owns Certificate Authority

**Status:** Accepted

**Context:** Certificates authenticate machine clients. We need to decide whether the CA belongs in Identity Service or Authorization Server.

**Decision:** Identity Service owns the CA function.

**Rationale:**
1. Certificates answer "who is this?" - an identity question
2. Certificate lifecycle is coupled to client identity lifecycle
3. Authorization Server should verify identity, not manage credentials
4. Consistent pattern: Identity will own passwords and federation links too

**Consequences:**
- (+) Clear conceptual boundary
- (+) Authorization Server stays focused on tokens
- (-) Cross-module call needed for certificate validation

---

### ADR-002: Modular Monolith with Strict Boundaries

**Status:** Accepted

**Decision:** Deploy as single service with strict module boundaries.

**Rules:**
- AuthZ module CAN call Identity module via internal API
- Identity module CANNOT call AuthZ module
- No cross-module database joins

---

### ADR-003: Subject Abstraction for Future Human Users

**Status:** Accepted

**Decision:** Introduce abstract `Subject` entity with `subject_type` discriminator.

---

## File Structure

```
identity-platform/
├── podman-compose.yml              # Orchestrates all services
├── README.md
├── docs/                           # Shared documentation
│
├── backend/                        # Python API (this phase)
│   ├── src/
│   │   ├── main.py
│   │   ├── shared/
│   │   │   ├── config.py
│   │   │   ├── database.py
│   │   │   ├── logging.py
│   │   │   └── metrics.py
│   │   ├── identity/               # Identity Module
│   │   │   ├── domain/
│   │   │   ├── api/
│   │   │   │   ├── clients.py
│   │   │   │   ├── approvals.py
│   │   │   │   └── internal.py     # ValidateCertificate
│   │   │   ├── services/
│   │   │   ├── ca/                 # Certificate Authority
│   │   │   ├── repository/
│   │   │   └── jobs/
│   │   └── authz/                  # Authorization Module
│   │       ├── domain/
│   │       ├── api/
│   │       │   ├── token.py
│   │       │   └── discovery.py
│   │       ├── services/
│   │       ├── validation/
│   │       ├── jwt/
│   │       ├── client/
│   │       │   └── identity_client.py
│   │       └── repository/
│   ├── tests/
│   ├── migrations/
│   ├── pyproject.toml
│   └── Dockerfile
│
├── webapi/                         # Sample Resource Server
│   └── ...
│
└── frontend/                       # Future: Admin UI (not in scope)
    └── ...
```

**Structure Rationale:**
- `/backend/src` enables future `/frontend` addition without restructuring
- Each component has its own `Dockerfile` for independent containerization
- Shared `podman-compose.yml` orchestrates all services
- `docs/` contains shared documentation accessible to all components

