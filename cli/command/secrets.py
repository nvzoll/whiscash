import argparse
import json
import secrets
from pathlib import Path

SECRETS_PATH = (Path(__file__) / ".." / ".." / ".." / ".secrets.json").resolve()


def parse_extra(args: list[str]) -> dict[str, str]:
    extra = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        if not sep:
            raise SystemExit(f"expected key=value, got {arg!r}")
        extra[key] = value
    return extra


def generate(args: argparse.Namespace) -> None:
    values = {
        "jwt_secret": secrets.token_urlsafe(32),
        **parse_extra(args.extra),
    }

    SECRETS_PATH.write_text(json.dumps(values, indent=2) + "\n")
    print(f"wrote {SECRETS_PATH}")


def register(subparsers: argparse._SubParsersAction) -> None:
    group = subparsers.add_parser("secrets", help="Manage .secrets.json")
    actions = group.add_subparsers(dest="action", required=True)

    generate_parser = actions.add_parser("generate", help="Generate JWT secrets")
    generate_parser.add_argument("extra", nargs="*", help="Additional key=value pairs to include")
    generate_parser.set_defaults(func=generate)
