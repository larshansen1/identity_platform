"""Pydantic schemas for Identity API request/response validation."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class CreateClientRequest(BaseModel):
    """Request body for creating a machine client."""

    display_name: str = Field(..., min_length=3, max_length=100)
    description: str | None = Field(None, max_length=500)


class ClientResponse(BaseModel):
    """Response model for a machine client."""

    subject_id: UUID
    display_name: str
    description: str | None
    status: str
    certificate_thumbprint: str | None
    certificate_not_after: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ClientListResponse(BaseModel):
    """Response model for listing machine clients."""

    items: list[ClientResponse]
    total: int


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    code: str
    detail: str | None = None
