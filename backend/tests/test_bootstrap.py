"""Tests for bootstrap service."""

from unittest.mock import AsyncMock, patch

import pytest

from identity.services.bootstrap import bootstrap_admin_if_needed


class TestBootstrap:
    """Tests for bootstrap_admin_if_needed."""

    @pytest.mark.asyncio
    async def test_bootstrap_skipped_when_admins_exist(self):
        """Test that bootstrap is skipped when admins already exist."""
        mock_db = AsyncMock()

        with patch("identity.services.bootstrap.AdminUserRepository") as MockRepo:
            mock_repo = AsyncMock()
            mock_repo.count_all.return_value = 1  # Admins exist
            MockRepo.return_value = mock_repo

            result = await bootstrap_admin_if_needed(mock_db)

            assert result is None
            mock_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_bootstrap_skipped_without_env_config(self):
        """Test that bootstrap is skipped when env vars not set."""
        mock_db = AsyncMock()

        with (
            patch("identity.services.bootstrap.AdminUserRepository") as MockRepo,
            patch("identity.services.bootstrap.settings") as mock_settings,
        ):
            mock_repo = AsyncMock()
            mock_repo.count_all.return_value = 0  # No admins
            MockRepo.return_value = mock_repo

            mock_settings.BOOTSTRAP_ADMIN_EMAIL = None  # Not configured

            result = await bootstrap_admin_if_needed(mock_db)

            assert result is None
            mock_repo.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_bootstrap_creates_admin_from_env(self):
        """Test that bootstrap creates admin when configured."""
        mock_db = AsyncMock()

        with (
            patch("identity.services.bootstrap.AdminUserRepository") as MockRepo,
            patch("identity.services.bootstrap.settings") as mock_settings,
            patch("identity.services.bootstrap.generate_api_key") as mock_gen_key,
            patch("identity.services.bootstrap.hash_api_key") as mock_hash_key,
            patch("identity.services.bootstrap.identity_metrics"),
        ):
            mock_repo = AsyncMock()
            mock_repo.count_all.return_value = 0  # No admins
            MockRepo.return_value = mock_repo

            mock_settings.BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
            mock_settings.BOOTSTRAP_ADMIN_NAME = "Admin User"
            mock_settings.BOOTSTRAP_ADMIN_ROLES = "requester,approver"
            mock_settings.BOOTSTRAP_APPROVER_EMAIL = None  # No second admin

            mock_gen_key.return_value = "idp_test_key_12345"
            mock_hash_key.return_value = "$argon2id$..."

            result = await bootstrap_admin_if_needed(mock_db)

            assert result == "idp_test_key_12345"
            mock_repo.create.assert_called_once()  # Only primary admin
            mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_bootstrap_admin_has_correct_roles(self):
        """Test that bootstrap admin has configured roles."""
        mock_db = AsyncMock()

        with (
            patch("identity.services.bootstrap.AdminUserRepository") as MockRepo,
            patch("identity.services.bootstrap.settings") as mock_settings,
            patch("identity.services.bootstrap.generate_api_key") as mock_gen_key,
            patch("identity.services.bootstrap.hash_api_key") as mock_hash_key,
            patch("identity.services.bootstrap.identity_metrics"),
        ):
            mock_repo = AsyncMock()
            mock_repo.count_all.return_value = 0
            MockRepo.return_value = mock_repo

            mock_settings.BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
            mock_settings.BOOTSTRAP_ADMIN_NAME = "Admin User"
            mock_settings.BOOTSTRAP_ADMIN_ROLES = "requester,approver"
            mock_settings.BOOTSTRAP_APPROVER_EMAIL = None  # No second admin

            mock_gen_key.return_value = "idp_test_key"
            mock_hash_key.return_value = "$argon2id$..."

            await bootstrap_admin_if_needed(mock_db)

            # Check the admin was created with correct roles
            call_args = mock_repo.create.call_args[0][0]
            assert "requester" in call_args.roles
            assert "approver" in call_args.roles

    @pytest.mark.asyncio
    async def test_bootstrap_returns_api_key(self):
        """Test that bootstrap returns the generated API key."""
        mock_db = AsyncMock()

        with (
            patch("identity.services.bootstrap.AdminUserRepository") as MockRepo,
            patch("identity.services.bootstrap.settings") as mock_settings,
            patch("identity.services.bootstrap.generate_api_key") as mock_gen_key,
            patch("identity.services.bootstrap.hash_api_key"),
            patch("identity.services.bootstrap.identity_metrics"),
        ):
            mock_repo = AsyncMock()
            mock_repo.count_all.return_value = 0
            MockRepo.return_value = mock_repo

            mock_settings.BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
            mock_settings.BOOTSTRAP_ADMIN_NAME = None  # Should default to email
            mock_settings.BOOTSTRAP_ADMIN_ROLES = "requester"
            mock_settings.BOOTSTRAP_APPROVER_EMAIL = None  # No second admin

            expected_key = "idp_unique_key_abc123"
            mock_gen_key.return_value = expected_key

            result = await bootstrap_admin_if_needed(mock_db)

            assert result == expected_key

    @pytest.mark.asyncio
    async def test_bootstrap_uses_email_as_name_if_not_provided(self):
        """Test that bootstrap uses email as name when name not provided."""
        mock_db = AsyncMock()

        with (
            patch("identity.services.bootstrap.AdminUserRepository") as MockRepo,
            patch("identity.services.bootstrap.settings") as mock_settings,
            patch("identity.services.bootstrap.generate_api_key") as mock_gen_key,
            patch("identity.services.bootstrap.hash_api_key"),
            patch("identity.services.bootstrap.identity_metrics"),
        ):
            mock_repo = AsyncMock()
            mock_repo.count_all.return_value = 0
            MockRepo.return_value = mock_repo

            mock_settings.BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
            mock_settings.BOOTSTRAP_ADMIN_NAME = None  # Not provided
            mock_settings.BOOTSTRAP_ADMIN_ROLES = "requester"
            mock_settings.BOOTSTRAP_APPROVER_EMAIL = None  # No second admin

            mock_gen_key.return_value = "idp_test"

            await bootstrap_admin_if_needed(mock_db)

            call_args = mock_repo.create.call_args[0][0]
            assert call_args.name == "admin@example.com"
