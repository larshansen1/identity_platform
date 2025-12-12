"""Client management API endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from shared.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

from identity.api.auth import require_role
from identity.api.schemas import (
    ClientListResponse,
    ClientResponse,
    CreateClientRequest,
)
from identity.ca.key_manager import KeyManager
from identity.domain.models import AdminUser
from identity.domain.states import AdminRole, MachineClientStatus
from identity.services.certificate_service import CertificateService, DownloadExpiredError
from identity.services.client_service import (
    ClientService,
    ConflictError,
    NotFoundError,
    RequestContext,
)

router = APIRouter(prefix="/api/clients", tags=["clients"])

# Global key manager instance (shared with approvals module)
_key_manager: KeyManager | None = None


def set_key_manager(km: KeyManager) -> None:
    """Set the global key manager instance."""
    global _key_manager
    _key_manager = km


def get_key_manager() -> KeyManager:
    """Get the global key manager instance."""
    if _key_manager is None:
        raise RuntimeError("KeyManager not initialized")
    return _key_manager


def get_request_context(request: Request) -> RequestContext:
    """Extract request context for audit logging."""
    return RequestContext(
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


def get_client_service(db: AsyncSession = Depends(get_db)) -> ClientService:
    """Dependency to get ClientService instance."""
    return ClientService(db)


def get_certificate_service(db: AsyncSession = Depends(get_db)) -> CertificateService:
    """Dependency to get CertificateService instance."""
    return CertificateService(db, get_key_manager())


# =============================================================================
# Request/Response Schemas for Certificate Requests
# =============================================================================


class CertificateRequestResponse(BaseModel):
    """Response for a certificate request."""

    request_id: str
    subject_id: str
    request_type: str
    status: str
    created_at: str
    expires_at: str
    download_expires_at: str | None = None


class CertificateBundleResponse(BaseModel):
    """Response containing the certificate bundle for download."""

    certificate_pem: str
    private_key_pem: str
    ca_certificate_pem: str
    subject_id: str


# =============================================================================
# Client CRUD Endpoints
# =============================================================================


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ClientResponse)
async def create_client(
    request: Request,
    body: CreateClientRequest,
    admin: AdminUser = Depends(require_role(AdminRole.REQUESTER)),
    service: ClientService = Depends(get_client_service),
) -> ClientResponse:
    """
    Create a new machine client.

    - Auth: API key with REQUESTER role
    - Returns: 201 Created with client details
    - Errors: 400 BAD_REQUEST (validation), 401 UNAUTHORIZED, 403 FORBIDDEN
    """
    context = get_request_context(request)
    client = await service.create_machine_client(
        owner=admin,
        display_name=body.display_name,
        description=body.description,
        request_context=context,
    )
    return ClientResponse.model_validate(client)


@router.get("", response_model=ClientListResponse)
async def list_clients(
    status_filter: MachineClientStatus | None = Query(None, alias="status"),
    limit: int = Query(default=20, le=100, ge=1),
    offset: int = Query(default=0, ge=0),
    admin: AdminUser = Depends(require_role(AdminRole.REQUESTER)),
    service: ClientService = Depends(get_client_service),
) -> ClientListResponse:
    """
    List machine clients owned by the current admin.

    - Auth: API key with REQUESTER role
    - Pagination: limit (max 100), offset
    - Filter: optional status
    """
    clients, total = await service.list_machine_clients(
        owner=admin,
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    return ClientListResponse(
        items=[ClientResponse.model_validate(c) for c in clients],
        total=total,
    )


@router.get("/{subject_id}", response_model=ClientResponse)
async def get_client(
    subject_id: UUID,
    admin: AdminUser = Depends(require_role(AdminRole.REQUESTER)),
    service: ClientService = Depends(get_client_service),
) -> ClientResponse:
    """
    Get a specific machine client.

    - Auth: API key with REQUESTER role
    - Constraint: Only returns if admin is owner (INV-13)
    - Errors: 404 NOT_FOUND if not found or not owned
    """
    try:
        client = await service.get_machine_client(owner=admin, subject_id=subject_id)
        return ClientResponse.model_validate(client)
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Machine client {subject_id} not found",
        ) from None


@router.delete("/{subject_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(
    request: Request,
    subject_id: UUID,
    admin: AdminUser = Depends(require_role(AdminRole.REQUESTER)),
    service: ClientService = Depends(get_client_service),
) -> None:
    """
    Delete (revoke) a machine client.

    - Auth: API key with REQUESTER role
    - Constraint: Only if admin is owner (INV-13)
    - Constraint: Client cannot be already REVOKED (INV-04)
    - Errors: 404 NOT_FOUND, 409 CONFLICT (already revoked)
    """
    context = get_request_context(request)
    try:
        await service.delete_machine_client(
            owner=admin,
            subject_id=subject_id,
            request_context=context,
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Machine client {subject_id} not found",
        ) from None
    except ConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        ) from None


# =============================================================================
# Certificate Request Endpoints
# =============================================================================


@router.post(
    "/{subject_id}/certificate-requests",
    status_code=status.HTTP_201_CREATED,
    response_model=CertificateRequestResponse,
)
async def create_certificate_request(
    request: Request,
    subject_id: UUID,
    admin: AdminUser = Depends(require_role(AdminRole.REQUESTER)),
    service: ClientService = Depends(get_client_service),
) -> CertificateRequestResponse:
    """
    Create a certificate request for a machine client.

    - Auth: API key with REQUESTER role
    - Constraint: Only if admin is owner (INV-13)
    - Constraint: Client cannot be REVOKED
    - Constraint: No pending request can exist (INV-05)
    """
    context = get_request_context(request)
    try:
        cert_request = await service.create_certificate_request(
            owner=admin,
            subject_id=subject_id,
            request_context=context,
        )
        return CertificateRequestResponse(
            request_id=str(cert_request.request_id),
            subject_id=str(cert_request.client_id),
            request_type=cert_request.request_type,
            status=cert_request.status,
            created_at=cert_request.created_at.isoformat(),
            expires_at=cert_request.expires_at.isoformat(),
            download_expires_at=(
                cert_request.download_expires_at.isoformat()
                if cert_request.download_expires_at
                else None
            ),
        )
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from None
    except ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from None


@router.get(
    "/{subject_id}/certificate-requests/{request_id}",
    response_model=CertificateRequestResponse,
)
async def get_certificate_request(
    subject_id: UUID,
    request_id: UUID,
    admin: AdminUser = Depends(require_role(AdminRole.REQUESTER)),
    service: ClientService = Depends(get_client_service),
) -> CertificateRequestResponse:
    """
    Get a certificate request.

    - Auth: API key with REQUESTER role
    - Constraint: Only if admin is owner (INV-13)
    """
    try:
        cert_request = await service.get_certificate_request(
            owner=admin,
            client_id=subject_id,
            request_id=request_id,
        )
        return CertificateRequestResponse(
            request_id=str(cert_request.request_id),
            subject_id=str(cert_request.client_id),
            request_type=cert_request.request_type,
            status=cert_request.status,
            created_at=cert_request.created_at.isoformat(),
            expires_at=cert_request.expires_at.isoformat(),
            download_expires_at=(
                cert_request.download_expires_at.isoformat()
                if cert_request.download_expires_at
                else None
            ),
        )
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from None


@router.get(
    "/{subject_id}/certificate-requests/{request_id}/download",
    response_model=CertificateBundleResponse,
)
async def download_certificate(
    request: Request,
    subject_id: UUID,
    request_id: UUID,
    admin: AdminUser = Depends(require_role(AdminRole.REQUESTER)),
    cert_service: CertificateService = Depends(get_certificate_service),
) -> CertificateBundleResponse:
    """
    Download a certificate bundle.

    - Auth: API key with REQUESTER role
    - Constraint: Only if admin is owner (INV-13)
    - Constraint: Request must be in ISSUED status
    - Constraint: Download window must not be expired
    """
    context = get_request_context(request)
    try:
        cert_request, client = await cert_service.get_request_for_download(
            request_id=request_id,
            client_id=subject_id,
            owner_id=admin.user_id,
        )
        bundle = await cert_service.download_certificate(
            request=cert_request,
            client=client,
            request_context=context,
        )
        return CertificateBundleResponse(**bundle)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from None
    except ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from None
    except DownloadExpiredError as e:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(e)) from None
