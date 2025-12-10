"""Bootstrap service for first-run initialization."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from identity.domain.models import AdminUser
from identity.metrics import identity_metrics
from identity.repository.repositories import AdminUserRepository
from shared.config import settings
from shared.security import generate_api_key, hash_api_key

logger = logging.getLogger(__name__)


async def bootstrap_admin_if_needed(db: AsyncSession) -> str | None:
    """
    Create bootstrap admin from environment if no admins exist.

    Environment variables:
    - BOOTSTRAP_ADMIN_EMAIL: Required to trigger bootstrap
    - BOOTSTRAP_ADMIN_NAME: Display name (defaults to email)
    - BOOTSTRAP_ADMIN_ROLES: Comma-separated roles (default: REQUESTER,APPROVER)

    Returns:
        Generated API key (shown once) or None if skipped

    Logs:
    - INFO bootstrap_started
    - INFO bootstrap_admin_created {email, roles}
    - DEBUG bootstrap_skipped {reason}

    Metrics:
    - identity_bootstrap_completed = 1
    - identity_admin_users_total{role=...} +1
    """
    admin_repo = AdminUserRepository(db)

    # Check if any admins exist
    count = await admin_repo.count_all()
    if count > 0:
        logger.debug("bootstrap_skipped", extra={"reason": "admins_exist"})
        return None

    # Check if bootstrap config is set
    if not settings.BOOTSTRAP_ADMIN_EMAIL:
        logger.debug("bootstrap_skipped", extra={"reason": "no_bootstrap_config"})
        return None

    logger.info("bootstrap_started")

    # Generate API key
    api_key = generate_api_key()
    api_key_hash = hash_api_key(api_key)

    # Parse roles
    roles = [r.strip().lower() for r in settings.BOOTSTRAP_ADMIN_ROLES.split(",")]

    # Create admin
    admin = AdminUser(
        email=settings.BOOTSTRAP_ADMIN_EMAIL,
        name=settings.BOOTSTRAP_ADMIN_NAME or settings.BOOTSTRAP_ADMIN_EMAIL,
        roles=roles,
        api_key_hash=api_key_hash,
    )
    await admin_repo.create(admin)
    await db.commit()

    logger.info(
        "bootstrap_admin_created",
        extra={"email": admin.email, "roles": roles},
    )

    # Log the API key (only shown once!)
    logger.info(f"Bootstrap API key (save this, shown once): {api_key}")

    # Update metrics
    identity_metrics.record_bootstrap_completed()
    for role in roles:
        identity_metrics.record_admin_created(role)

    return api_key
