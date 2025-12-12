"""Bootstrap service for first-run initialization."""

import logging

from shared.config import settings
from shared.security import generate_api_key, hash_api_key
from sqlalchemy.ext.asyncio import AsyncSession

from identity.domain.models import AdminUser
from identity.metrics import identity_metrics
from identity.repository.repositories import AdminUserRepository

logger = logging.getLogger(__name__)

# Distinct banner for easy grep in logs
API_KEY_BANNER = "=" * 60


def _print_api_key(email: str, api_key: str) -> None:
    """Print API key with clear formatting for easy discovery."""
    # Use print() for immediate visibility (not buffered like logging)
    print(f"\n{API_KEY_BANNER}")
    print(f"BOOTSTRAP API KEY - {email}")
    print(f"{api_key}")
    print(f"{API_KEY_BANNER}\n")
    # Also log for structured output
    logger.info("bootstrap_api_key_generated", extra={"email": email})


async def _create_admin(
    admin_repo: AdminUserRepository,
    email: str,
    name: str | None,
    roles: list[str],
) -> tuple[AdminUser, str]:
    """Create an admin user and return (admin, api_key)."""
    api_key = generate_api_key()
    api_key_hash = hash_api_key(api_key)

    admin = AdminUser(
        email=email,
        name=name or email,
        roles=roles,
        api_key_hash=api_key_hash,
    )
    await admin_repo.create(admin)

    logger.info(
        "bootstrap_admin_created",
        extra={"email": admin.email, "roles": roles},
    )

    # Print API key with clear formatting
    _print_api_key(email, api_key)

    # Record metrics
    for role in roles:
        identity_metrics.record_admin_created(role)

    return admin, api_key


async def bootstrap_admin_if_needed(db: AsyncSession) -> str | None:
    """
    Create bootstrap admin(s) from environment if no admins exist.

    Environment variables:
    - BOOTSTRAP_ADMIN_EMAIL: Required to trigger bootstrap (requester admin)
    - BOOTSTRAP_ADMIN_NAME: Display name (defaults to email)
    - BOOTSTRAP_ADMIN_ROLES: Comma-separated roles (default: REQUESTER,APPROVER)
    - BOOTSTRAP_APPROVER_EMAIL: Optional second admin (approver-only, for testing)
    - BOOTSTRAP_APPROVER_NAME: Display name for second admin

    API keys are printed to stdout with a distinct banner. Grep for '====' in logs.

    Returns:
        Generated API key for first admin, or None if skipped
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

    # Create primary admin (requester with optional approver role)
    roles = [r.strip().lower() for r in settings.BOOTSTRAP_ADMIN_ROLES.split(",")]
    admin, api_key = await _create_admin(
        admin_repo,
        settings.BOOTSTRAP_ADMIN_EMAIL,
        settings.BOOTSTRAP_ADMIN_NAME,
        roles,
    )

    # Create second admin (approver-only) if configured
    approver_email = getattr(settings, "BOOTSTRAP_APPROVER_EMAIL", None)
    if approver_email:
        approver_name = getattr(settings, "BOOTSTRAP_APPROVER_NAME", None)
        await _create_admin(
            admin_repo,
            approver_email,
            approver_name,
            ["approver"],
        )

    await db.commit()

    # Update metrics
    identity_metrics.record_bootstrap_completed()

    return api_key
