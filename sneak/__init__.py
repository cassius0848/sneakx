"""sneak: E2E encrypted terminal chat with SRP authentication."""

import argparse

from .server import run_server
from .client import Client


def main():
    parser = argparse.ArgumentParser(
        description="End-to-end encrypted terminal chat"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── Server ─────────────────────────────────────────────
    serve_p = subparsers.add_parser("serve", help="Start chat server")
    serve_p.add_argument("ip_address", help="Bind address (e.g., 0.0.0.0)")
    serve_p.add_argument("port", type=int, help="Listen port")
    serve_p.add_argument(
        "--password", "-p", required=True, help="Room password (used for SRP auth)"
    )

    # ── Client ─────────────────────────────────────────────
    connect_p = subparsers.add_parser("connect", help="Join chat server")
    connect_p.add_argument("ip_address", help="Server IP or hostname")
    connect_p.add_argument("port", type=int, help="Server port")
    connect_p.add_argument("username", help="Display name")
    connect_p.add_argument("password", help="Room password")

    args = parser.parse_args()

    if args.command == "serve":
        run_server(host=args.ip_address, port=args.port, password=args.password)
    elif args.command == "connect":
        Client(
            server=args.ip_address,
            port=args.port,
            username=args.username,
            password=args.password,
        ).run()


if __name__ == "__main__":
    main()
