import hashlib
import hmac
import secrets
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

from .schemas import Identifier, LanguagePlugin


SESSION_HEADER = "X-CodeBloodhound-Session"
PASSWORD_SALT_BYTES = 16


class Credentials(BaseModel):
    username: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,39}$")]
    password: Annotated[str, StringConstraints(min_length=10, max_length=128)]


class PluginSelection(BaseModel):
    languagePlugins: list[LanguagePlugin] = Field(max_length=2)


class Account(PluginSelection):
    id: Identifier
    username: str


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
