"""Local CLI for secure initial Administrator provisioning."""

import sys
import warnings
from getpass import getpass, GetPassWarning
from pathlib import Path

import psycopg
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env", override=True)

from app.services.auth_bootstrap_service import (
    bootstrap_admin,
    BootstrapError,
    normalize_identity,
)

from app.services.auth_security_service import validate_password


def main():
    if not sys.stdin.isatty():
        print("ERROR: Interactive terminal required.")
        return 1

    print("\n=== INTELSOC ADMINISTRATOR SETUP ===")
    print("Local provisioning for authorized system owners.")
    print("Password must contain at least 15 characters.")

    try:
        while True:
            username = input("Username: ").strip()

            try:
                normalize_identity(username, "validation@example.com")
                break
            except ValueError as error:
                print("ERROR:", error)

        while True:
            email = input("Email address: ").strip()

            try:
                username, email = normalize_identity(username, email)
                break
            except ValueError as error:
                print("ERROR:", error)

        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)

            while True:
                password = getpass("Password: ")

                try:
                    validate_password(password)
                except ValueError as error:
                    print("ERROR:", error)
                    continue

                confirmation = getpass("Confirm password: ")

                if password != confirmation:
                    print("ERROR: Passwords do not match. Try again.")
                    continue

                break

        result = bootstrap_admin(
            username=username,
            email=email,
            password=password,
        )

        print("\n=== ADMINISTRATOR CREATED ===")
        print("User ID:", result["user_id"])
        print("Username:", result["username"])
        print("Email:", result["email"])
        print("Role:", result["role"])
        print("Status:", result["status"])
        print("Bootstrap: COMPLETED")

        return 0

    except (BootstrapError, ValueError) as error:
        print("ERROR:", str(error))
        return 1

    except psycopg.errors.UniqueViolation:
        print("ERROR: Username or email already exists.")
        return 1

    except psycopg.Error:
        print("ERROR: Administrator provisioning failed.")
        return 1

    except GetPassWarning:
        print("ERROR: Secure password input unavailable.")
        return 1

    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
