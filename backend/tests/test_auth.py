"""Tests for API key authentication."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from identity.api.auth import get_current_admin, require_role
from identity.domain.models import AdminUser
from identity.domain.states import AdminRole


def create_mock_admin(roles: list[str] | None = None) -> AdminUser:
    """Create a mock AdminUser."""
    admin = MagicMock(spec=AdminUser)
    admin.user_id = uuid4()
    admin.email = "test@example.com"
    admin.roles = roles or [AdminRole.REQUESTER.value]
    admin.api_key_hash = "$argon2id$test_hash"
    admin.has_role = lambda r: r.value in admin.roles
    return admin


class TestApiKeyAuth:
    """Tests for get_current_admin authentication."""

    @pytest.mark.asyncio
    async def test_missing_api_key_raises_401(self):
        """Test that missing API key raises 401."""
        mock_db = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await get_current_admin(api_key=None, db=mock_db)

        assert exc_info.value.status_code == 401
        assert "Missing API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_invalid_format_raises_401(self):
        """Test that invalid API key format raises 401."""
        mock_db = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await get_current_admin(api_key="invalid_format_key", db=mock_db)

        assert exc_info.value.status_code == 401
        assert "Invalid API key format" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_unknown_api_key_raises_401(self):
        """Test that unknown API key raises 401."""
        mock_db = AsyncMock()

        with patch("identity.api.auth.verify_api_key"):
            # Setup mock to return no matching admin
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_db.execute.return_value = mock_result

            with pytest.raises(HTTPException) as exc_info:
                await get_current_admin(api_key="idp_unknown_key_123", db=mock_db)

            assert exc_info.value.status_code == 401
            assert "Invalid API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_valid_api_key_returns_admin(self):
        """Test that valid API key returns admin."""
        mock_db = AsyncMock()
        admin = create_mock_admin()

        with patch("identity.api.auth.verify_api_key") as mock_verify:
            mock_verify.return_value = True

            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = [admin]
            mock_db.execute.return_value = mock_result

            result = await get_current_admin(api_key="idp_valid_key_123", db=mock_db)

            assert result == admin


class TestRequireRole:
    """Tests for role-based authorization."""

    @pytest.mark.asyncio
    async def test_admin_with_role_passes(self):
        """Test that admin with required role passes."""
        admin = create_mock_admin([AdminRole.REQUESTER.value])

        # Create the check function - require_role returns an async function
        check_fn = require_role(AdminRole.REQUESTER)

        # Call the function directly with the admin (simulating dependency injection)
        result = await check_fn(admin)
        assert result == admin

    @pytest.mark.asyncio
    async def test_admin_without_role_raises_403(self):
        """Test that admin without required role raises 403."""
        admin = create_mock_admin([AdminRole.APPROVER.value])  # Has APPROVER, not REQUESTER

        check_fn = require_role(AdminRole.REQUESTER)

        with pytest.raises(HTTPException) as exc_info:
            await check_fn(admin)

        assert exc_info.value.status_code == 403
        assert "requester" in exc_info.value.detail.lower()
