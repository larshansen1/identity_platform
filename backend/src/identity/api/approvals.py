"""API endpoints for certificate request approval workflow.

Requires APPROVER role for all endpoints.
"""

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from shared.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession

from identity.api.auth import require_role
from identity.ca.key_manager import KeyManager
from identity.domain.models import AdminUser
from identity.domain.states import AdminRole
from identity.services.approval_service import ApprovalService, SelfApprovalError
from identity.services.client_service import (
    ConflictError,
    NotFoundError,
    RequestContext,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/approvals", tags=["approvals"])

# Global key manager instance (initialized on startup)
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


def get_approval_service(db: AsyncSession = Depends(get_db)) -> ApprovalService:
    """Dependency to get ApprovalService."""
    return ApprovalService(db, get_key_manager())


def get_request_context(request: Request) -> RequestContext:
    """Extract request context for audit logging."""
    return RequestContext(
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


# =============================================================================
# Request/Response Schemas
# =============================================================================


class PendingRequestResponse(BaseModel):
    """Pending request in the approval queue."""

    request_id: str
    subject_id: str
    client_display_name: str
    owner_email: str
    request_type: str
    created_at: str


class PendingListResponse(BaseModel):
    """List of pending requests with pagination."""

    items: list[PendingRequestResponse]
    total: int


class ApprovalResultResponse(BaseModel):
    """Response after approving a request."""

    request_id: str
    status: str
    decided_at: str


class RejectRequestBody(BaseModel):
    """Request body for rejecting a certificate request."""

    reason: str = Field(..., min_length=10, max_length=500, description="Rejection reason")


class RejectionResultResponse(BaseModel):
    """Response after rejecting a request."""

    request_id: str
    status: str
    rejection_reason: str
    decided_at: str


# =============================================================================
# Endpoints
# =============================================================================


@router.get("/pending", response_model=PendingListResponse)
async def list_pending(
    limit: int = 20,
    offset: int = 0,
    admin: AdminUser = Depends(require_role(AdminRole.APPROVER)),
    service: ApprovalService = Depends(get_approval_service),
) -> PendingListResponse:
    """List pending certificate requests for approval.

    Requires APPROVER role.
    """
    items, total = await service.list_pending(limit=limit, offset=offset)
    return PendingListResponse(
        items=[PendingRequestResponse(**item) for item in items],
        total=total,
    )


@router.post("/{request_id}/approve", response_model=ApprovalResultResponse)
async def approve_request(
    request_id: UUID,
    request: Request,
    admin: AdminUser = Depends(require_role(AdminRole.APPROVER)),
    service: ApprovalService = Depends(get_approval_service),
) -> ApprovalResultResponse:
    """Approve a certificate request.

    Requires APPROVER role.
    Cannot approve your own client's request (INV-06).
    """
    request_context = get_request_context(request)

    try:
        cert_request = await service.approve(
            approver=admin,
            request_id=request_id,
            request_context=request_context,
        )
        return ApprovalResultResponse(
            request_id=str(cert_request.request_id),
            status=cert_request.status,
            decided_at=cert_request.decided_at.isoformat() if cert_request.decided_at else "",
        )
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None
    except SelfApprovalError as e:
        raise HTTPException(status_code=403, detail=str(e)) from None
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=str(e)) from None


@router.post("/{request_id}/reject", response_model=RejectionResultResponse)
async def reject_request(
    request_id: UUID,
    body: RejectRequestBody,
    request: Request,
    admin: AdminUser = Depends(require_role(AdminRole.APPROVER)),
    service: ApprovalService = Depends(get_approval_service),
) -> RejectionResultResponse:
    """Reject a certificate request with a reason.

    Requires APPROVER role.
    Reason is mandatory (INV-07).
    """
    request_context = get_request_context(request)

    try:
        cert_request = await service.reject(
            approver=admin,
            request_id=request_id,
            reason=body.reason,
            request_context=request_context,
        )
        return RejectionResultResponse(
            request_id=str(cert_request.request_id),
            status=cert_request.status,
            rejection_reason=cert_request.rejection_reason or "",
            decided_at=cert_request.decided_at.isoformat() if cert_request.decided_at else "",
        )
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
