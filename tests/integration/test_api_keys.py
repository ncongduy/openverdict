import pytest

from openverdict.models.api_keys import ApiKeyRepo, KeyNameTaken, Role, hash_key


async def test_create_authenticate_revoke(db):
    repo = ApiKeyRepo(db)
    principal, key = await repo.create("app", Role.CLIENT)
    assert key.startswith("ov_") and len(key) > 40 and hash_key(key) != key
    assert await repo.authenticate(key) == principal
    assert principal.role is Role.CLIENT and principal.name == "app"
    assert await repo.authenticate("ov_wrong") is None
    assert await repo.revoke("app") is True
    assert await repo.authenticate(key) is None
    assert await repo.revoke("missing") is False


async def test_duplicate_name(db):
    repo = ApiKeyRepo(db)
    await repo.create("dup", Role.ANALYST)
    with pytest.raises(KeyNameTaken):
        await repo.create("dup", Role.CLIENT)
