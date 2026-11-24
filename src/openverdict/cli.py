"""`openverdict` command line: migrate the database and manage API keys."""

import argparse
import asyncio
import sys

import uvicorn

from openverdict.config import Settings
from openverdict.logs import configure_logging
from openverdict.models.api_keys import ApiKeyRepo, KeyNameTaken, Role
from openverdict.models.db import create_engine, create_sessionmaker, run_migrations


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openverdict")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("api", help="run the HTTP API")
    commands.add_parser("migrate", help="upgrade the database schema")
    create = commands.add_parser("create-key", help="create an API key and print it once")
    create.add_argument("--name", required=True)
    create.add_argument("--role", required=True, choices=[role.value for role in Role])
    revoke = commands.add_parser("revoke-key", help="revoke an API key by name")
    revoke.add_argument("--name", required=True)
    return parser


async def _create_key(settings: Settings, name: str, role: Role) -> int:
    engine = create_engine(settings.database_url)
    try:
        _, key = await ApiKeyRepo(create_sessionmaker(engine)).create(name, role)
    except KeyNameTaken:
        print(f"a key named {name!r} already exists", file=sys.stderr)
        return 1
    finally:
        await engine.dispose()
    print(key)
    return 0


async def _revoke_key(settings: Settings, name: str) -> int:
    engine = create_engine(settings.database_url)
    try:
        revoked = await ApiKeyRepo(create_sessionmaker(engine)).revoke(name)
    finally:
        await engine.dispose()
    if not revoked:
        print(f"no active key named {name!r}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse exits on --help and bad arguments
        return exc.code if isinstance(exc.code, int) else 1
    settings = Settings()
    match args.command:
        case "api":
            configure_logging(settings.log_level)
            uvicorn.run(
                "openverdict.main:create_app",
                factory=True,
                host=settings.api_host,
                port=settings.api_port,
                log_config=None,
                access_log=False,
            )
            return 0
        case "migrate":
            run_migrations(settings.database_url)
            return 0
        case "create-key":
            return asyncio.run(_create_key(settings, args.name, Role(args.role)))
        case "revoke-key":
            return asyncio.run(_revoke_key(settings, args.name))
    return 2


if __name__ == "__main__":
    sys.exit(main())
