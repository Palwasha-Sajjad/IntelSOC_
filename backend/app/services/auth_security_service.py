"""Password hashing and secure token utilities for IntelSOC."""

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.low_level import Type
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)


MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128

PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def validate_password(password: str) -> None:
    """Validate a new account password."""

    if not isinstance(password, str):
        raise ValueError("Password must be a string")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            "Password must contain at least 15 characters"
        )

    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            "Password must not exceed 128 characters"
        )

    if not password.strip():
        raise ValueError("Password must not be blank")


def hash_password(password: str) -> str:
    """Generate a salted Argon2id password hash."""

    validate_password(password)

    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify credentials without exposing hashing errors."""

    if not isinstance(password, str):
        return False

    if not isinstance(stored_hash, str):
        return False

    if not password or len(password) > MAX_PASSWORD_LENGTH:
        return False

    if not stored_hash.startswith("$argon2id$"):
        return False

    try:
        return PASSWORD_HASHER.verify(
            stored_hash,
            password,
        )

    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError,
    ):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    """Identify hashes requiring updated security parameters."""

    if not isinstance(stored_hash, str):
        return True

    if not stored_hash.startswith("$argon2id$"):
        return True

    try:
        return PASSWORD_HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


def generate_secure_token() -> str:
    """Generate a URL-safe token with 256 bits of randomness."""

    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Generate the SHA-256 digest stored in PostgreSQL."""

    if not isinstance(token, str) or not token:
        raise ValueError("Invalid token")

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()
