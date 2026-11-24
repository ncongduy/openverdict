"""Shared controller dependencies: app resources and API-key authentication."""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Header, HTTPException, Request

from openverdict.models.api_keys import Principal, Role
from openverdict.resources import Resources


def get_resources(request: Request) -> Resources:
    resources: Resources = request.app.state.resources
    return resources


def require(*roles: Role) -> Callable[..., Awaitable[Principal]]:
    async def authenticate(
        request: Request, x_api_key: Annotated[str | None, Header()] = None
    ) -> Principal:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="invalid_api_key")
        principal = await get_resources(request).keys.authenticate(x_api_key)
        if principal is None:
            raise HTTPException(status_code=401, detail="invalid_api_key")
        if principal.role not in roles:
            raise HTTPException(status_code=403, detail="forbidden")
        return principal

    return authenticate
