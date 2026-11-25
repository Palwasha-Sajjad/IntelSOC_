import hashlib

import pytest

from app.services.auth_security_service import (
    validate_password,
    hash_password,
    verify_password,
    password_needs_rehash,
    generate_secure_token,
    hash_token,
)


@pytest.mark.parametrize("password", [
    "",
    "short",
    "a" * 14,
    "a" * 129,
    " " * 15,
    None,
])
def test_invalid_password(password):
    with pytest.raises(ValueError):
        validate_password(password)


@pytest.mark.parametrize("password", [
    "a" * 15,
    "a" * 128,
    "IntelSOC secure test passphrase",
])
def test_valid_password(password):
    validate_password(password)


def test_argon2id_hash():
    password = "IntelSOC-Test-Passphrase"
    hashed = hash_password(password)

    assert hashed.startswith("$argon2id$")
    assert hashed != password


def test_correct_password():
    password = "IntelSOC-Test-Passphrase"
    hashed = hash_password(password)

    assert verify_password(password, hashed)


def test_incorrect_password():
    hashed = hash_password("IntelSOC-Test-Passphrase")

    assert not verify_password(
        "Incorrect-Test-Passphrase",
        hashed,
    )


def test_unique_password_salts():
    password = "IntelSOC-Test-Passphrase"

    assert hash_password(password) != hash_password(password)


@pytest.mark.parametrize("stored_hash", [
    None,
    "",
    "plaintext-password",
    "$argon2id$invalid",
])
def test_invalid_stored_hash(stored_hash):
    assert not verify_password(
        "IntelSOC-Test-Passphrase",
        stored_hash,
    )


def test_invalid_password_input():
    assert not verify_password(None, "invalid-hash")


def test_current_hash_parameters():
    hashed = hash_password("IntelSOC-Test-Passphrase")

    assert not password_needs_rehash(hashed)


def test_invalid_hash_requires_rehash():
    assert password_needs_rehash("invalid-hash")


def test_secure_token_generation():
    token = generate_secure_token()

    assert isinstance(token, str)
    assert len(token) == 43


def test_token_uniqueness():
    tokens = {
        generate_secure_token()
        for _ in range(1000)
    }

    assert len(tokens) == 1000


def test_token_hash():
    token = generate_secure_token()
    digest = hash_token(token)

    assert len(digest) == 64
    assert digest != token
    assert digest == hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def test_token_hash_consistency():
    token = generate_secure_token()

    assert hash_token(token) == hash_token(token)


def test_different_token_hashes():
    first = generate_secure_token()
    second = generate_secure_token()

    assert hash_token(first) != hash_token(second)


@pytest.mark.parametrize("token", ["", None, 123])
def test_invalid_token(token):
    with pytest.raises(ValueError):
        hash_token(token)
