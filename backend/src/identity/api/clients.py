"""Client management API endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from identity.api.auth import require_role
from identity.api.schemas import (
    ClientListResponse,
    ClientResponse,
    CreateClientRequest,
)
from identity.domain.models import AdminUser
from identity.domain.states import AdminRole, MachineClientStatus
from identity.services.client_service import (
    ClientService,
    ConflictError,
    NotFoundError,
    RequestContext,
)
from shared.database import get_db

router = APIRouter(prefix="/api/clients", tags=["clients"])


def get_request_context(request: Request) -> RequestContext:
    """Extract request context for audit logging."""
    return RequestContext(
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


def get_client_service(db: AsyncSession = Depends(get_db)) -> ClientService:
    """Dependency to get ClientService instance."""
    return ClientService(db)


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
