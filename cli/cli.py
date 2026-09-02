import argparse

from cli.command import secrets, service_key

COMMANDS = [secrets, service_key]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cli", description="Whiscash operational CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in COMMANDS:
        command.register(subparsers)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
