"""Tests for shared security utilities."""

from shared.security import generate_api_key, hash_api_key, verify_api_key


class TestApiKeySecurity:
    """Tests for API key generation and verification."""

    def test_generate_api_key_format(self):
        """Test that generated API key has correct format."""
        api_key = generate_api_key()

        assert api_key.startswith("idp_")
        # Base64url encoded 32 bytes = ~43 chars
        assert len(api_key) > 40

    def test_generate_api_key_unique(self):
        """Test that each generated API key is unique."""
        keys = [generate_api_key() for _ in range(100)]
        assert len(set(keys)) == 100

    def test_hash_api_key_returns_string(self):
        """Test that hash_api_key returns a non-empty string."""
        api_key = generate_api_key()
        hashed = hash_api_key(api_key)

        assert isinstance(hashed, str)
        assert len(hashed) > 0
        # Argon2 hashes start with $argon2
        assert hashed.startswith("$argon2")

    def test_hash_api_key_unique_per_call(self):
        """Test that same API key produces different hashes (salted)."""
        api_key = generate_api_key()
        hash1 = hash_api_key(api_key)
        hash2 = hash_api_key(api_key)

        # Argon2 uses random salt, so hashes should differ
        assert hash1 != hash2

    def test_verify_api_key_correct(self):
        """Test that correct API key verifies successfully."""
        api_key = generate_api_key()
        hashed = hash_api_key(api_key)

        assert verify_api_key(api_key, hashed) is True

    def test_verify_api_key_incorrect(self):
        """Test that incorrect API key fails verification."""
        api_key = generate_api_key()
        hashed = hash_api_key(api_key)

        wrong_key = generate_api_key()
        assert verify_api_key(wrong_key, hashed) is False

    def test_verify_api_key_tampered(self):
        """Test that tampered API key fails verification."""
        api_key = generate_api_key()
        hashed = hash_api_key(api_key)

        tampered_key = api_key + "x"
        assert verify_api_key(tampered_key, hashed) is False
