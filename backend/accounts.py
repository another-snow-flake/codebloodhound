import hashlib
import hmac
import re
import secrets
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, field_validator

from .schemas import Identifier, LanguagePlugin


SESSION_HEADER = "X-CodeBloodhound-Session"
PASSWORD_SALT_BYTES = 16
EMAIL_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+"
EMAIL_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
EMAIL_PATTERN = re.compile(rf"{EMAIL_ATOM}(?:\.{EMAIL_ATOM})*@(?:{EMAIL_LABEL}\.)+{EMAIL_LABEL}")


class Credentials(BaseModel):
    username: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,39}$")]
    password: Annotated[str, StringConstraints(min_length=10, max_length=128)]


class RegistrationCredentials(Credentials):
    email: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=254)]
    confirmPassword: Annotated[str, StringConstraints(min_length=10, max_length=128)]

    @field_validator("email")
    @classmethod
    def validate_email(cls, email: str) -> str:
        if len(email.partition("@")[0]) > 64 or not EMAIL_PATTERN.fullmatch(email):
            raise ValueError("Enter a valid email address.")
        return email.lower()


class PluginSelection(BaseModel):
    languagePlugins: list[LanguagePlugin] = Field(max_length=2)


class Account(PluginSelection):
    id: Identifier
    username: str
    email: str | None = None


class Session(BaseModel):
    token: str
    account: Account


def _derive_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024)


def password_hash(password: str) -> bytes:
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    return salt + _derive_password(password, salt)


def verify_password(password: str, stored: bytes | None) -> bool:
    salt = stored[:PASSWORD_SALT_BYTES] if stored else bytes(PASSWORD_SALT_BYTES)
    candidate = _derive_password(password, salt)
    return stored is not None and hmac.compare_digest(candidate, stored[PASSWORD_SALT_BYTES:])


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()
