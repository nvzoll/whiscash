import json
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet

SECRETS_PATH = Path(__file__).resolve().parent.parent / ".secrets.json"


def parse_extra(args: list[str]) -> dict[str, str]:
    extra = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        if not sep:
            raise SystemExit(f"expected key=value, got {arg!r}")
        extra[key] = value
    return extra


if __name__ == "__main__":
    existing = {}
    if SECRETS_PATH.exists():
        existing = json.loads(SECRETS_PATH.read_text())
        existing.pop("sops", None)

    merged = {
        **existing,
        "jwt_secret": secrets.token_urlsafe(32),
        "refresh_token_key": Fernet.generate_key().decode(),
        **parse_extra(sys.argv[1:]),
    }

    SECRETS_PATH.write_text(json.dumps(merged, indent=2) + "\n")
    print(f"wrote {SECRETS_PATH}")
