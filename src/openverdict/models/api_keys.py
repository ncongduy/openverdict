"""API keys: random high-entropy secrets, stored only as SHA-256 hashes."""

import hashlib
import secrets
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from openverdict.models.tables import ApiKeyRow

KEY_PREFIX = "ov_"


class Role(StrEnum):
    CLIENT = "client"
    ANALYST = "analyst"


@dataclass(frozen=True, slots=True)
class Principal:
    key_id: int
    name: str
    role: Role


class KeyNameTaken(Exception):
    pass


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    # 32 random bytes cannot be brute-forced, so a fast hash is enough (unlike passwords).
    return hashlib.sha256(key.encode()).hexdigest()


class ApiKeyRepo:
    def __init__(self, db: async_sessionmaker[AsyncSession]) -> None:
        self._db = db

    async def create(self, name: str, role: Role) -> tuple[Principal, str]:
        key = generate_key()
        row = ApiKeyRow(name=name, role=role.value, key_hash=hash_key(key))
        try:
            async with self._db() as session, session.begin():
                session.add(row)
        except IntegrityError as exc:
            raise KeyNameTaken(name) from exc
        return Principal(key_id=row.id, name=name, role=role), key

    async def authenticate(self, key: str) -> Principal | None:
        query = select(ApiKeyRow).where(
            ApiKeyRow.key_hash == hash_key(key), ApiKeyRow.revoked_at.is_(None)
        )
        async with self._db() as session:
            row = (await session.execute(query)).scalar_one_or_none()
        if row is None:
            return None
        return Principal(key_id=row.id, name=row.name, role=Role(row.role))

    async def revoke(self, name: str) -> bool:
        statement = (
            update(ApiKeyRow)
            .where(ApiKeyRow.name == name, ApiKeyRow.revoked_at.is_(None))
            .values(revoked_at=func.now())
            .returning(ApiKeyRow.id)
        )
        async with self._db() as session, session.begin():
            revoked = (await session.execute(statement)).scalar_one_or_none()
        return revoked is not None
