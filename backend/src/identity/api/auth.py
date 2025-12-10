"""API key authentication for Identity API (INV-24)."""

import logging
from collections.abc import Coroutine
from typing import Any, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from identity.domain.models import AdminUser
from identity.domain.states import AdminRole
from shared.database import get_db
from shared.security import verify_api_key

logger = logging.getLogger(__name__)

# Define API key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_admin(
    api_key: str | None = Depends(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    """
    Authenticate admin via API key (INV-24).

    - Extract API key from X-API-Key header
    - Verify format: idp_<base64url>
    - Hash with Argon2id and lookup in database
    - Return AdminUser or raise 401 UNAUTHORIZED

    Log: DEBUG auth_attempt {result: success|failure}
    """
    if not api_key:
        logger.debug("auth_attempt", extra={"result": "failure", "reason": "missing_key"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )

    # Verify format
    if not api_key.startswith("idp_"):
        logger.debug("auth_attempt", extra={"result": "failure", "reason": "invalid_format"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format",
        )

    # Look up all admins and verify (argon2 hashes are unique per hash)
    # In production with many admins, consider caching or different approach
    result = await db.execute(select(AdminUser))
    admins = result.scalars().all()

    for admin in admins:
        if verify_api_key(api_key, admin.api_key_hash):
            logger.debug(
                "auth_attempt",
                extra={"result": "success", "admin_id": str(admin.user_id)},
            )
            return admin

    logger.debug("auth_attempt", extra={"result": "failure", "reason": "invalid_key"})
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


def require_role(role: AdminRole) -> Callable[[AdminUser], Coroutine[Any, Any, AdminUser]]:
    """
    Dependency factory for role-based authorization.

    Usage:
        @router.get("/protected")
        async def protected_route(admin: AdminUser = Depends(require_role(AdminRole.REQUESTER))):
            ...
    """

    async def check_role(admin: AdminUser = Depends(get_current_admin)) -> AdminUser:
        if not admin.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {role.value} role",
            )
        return admin

    return check_role
