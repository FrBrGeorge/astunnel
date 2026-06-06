"""
Cascaded command line argument parsers and entry points for the tunnel package.
Exposes a unified executable executing both server-side daemon and client connections.
"""

import sys
import argparse
import asyncio
from typing import List, Optional

from astunnel.client import TunnelClient
from astunnel.server import TunnelServer


def parse_ip_bytes(ip_str: str) -> bytes:
    """Converts standard A.B.C.D IPv4 string to 4-octet bytes."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        raise ValueError("IPv4 Client ID must be written as A.B.C.D")
    try:
        val = bytes(int(p) for p in parts)
        return val
    except Exception:
        raise ValueError("Invalid octet in Client ID")


PADDING_STR_MAP = {
    "none": 1,      # PADDING_NONE
    "full": 2,      # PADDING_FULL
    "random": 3,    # PADDING_RANDOM
}


def get_cli_parser() -> argparse.ArgumentParser:
    """
    Creates a cascaded command-line argument parser.
    Level 1: Common parameters (logging, padding, and sync timeout).
    Level 2: Subcommands 'server' and 'client'.
    Level 3: Backend sub-options (e.g. --backend, and echo filtering options).
    """
    # 1. ROOT PARSER (Common Parameters)
    root_parser = argparse.ArgumentParser(
        description="Asyncio SSL TCP Packet-Tunneling Gateway Utility",
        add_help=False,
    )
    common_group = root_parser.add_argument_group("Logging Configurations")
    common_group.add_argument(
        "--console-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Log level for standard console output (default: WARNING)",
    )
    common_group.add_argument(
        "--file-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Log level for the file output logs (default: INFO)",
    )
    common_group.add_argument(
        "--logfile",
        default=None,
        type=str,
        help="Path to save log files (disabled if omitted)",
    )

    tunnel_group = root_parser.add_argument_group("Tunnel Configurations")
    tunnel_group.add_argument(
        "--padding",
        default="none",
        choices=["none", "full", "random"],
        help="Padding mode: none, full, random (default: none)",
    )
    tunnel_group.add_argument(
        "--timeout",
        default=0.5,
        type=float,
        help="Sync timeout in float seconds. 0.0 means immediate send (default: 0.5)",
    )

    # 2. MAIN PARSER inherits root options
    main_parser = argparse.ArgumentParser(parents=[root_parser])
    subparsers = main_parser.add_subparsers(dest="command", required=True, help="Mode of execution")

    # ---- SERVER SUBCOMMAND ----
    srv_parser = subparsers.add_parser(
        "server",
        parents=[root_parser],
        help="Run SSL Tunnel Server listening node",
    )
    srv_parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="IP address to bind the server socket to (default: 0.0.0.0)",
    )
    srv_parser.add_argument(
        "--port",
        default=18443,
        type=int,
        help="TCP Port to listen on (default: 18443)",
    )
    srv_parser.add_argument(
        "--pem",
        default="server.pem",
        help="Path to combine SSL Certificate & Private Key PEM file (default: server.pem)",
    )

    # Backend specification for server
    srv_backend_group = srv_parser.add_argument_group("Server Backend Configurations")
    srv_backend_group.add_argument(
        "--backend",
        default="echo",
        choices=["echo"],
        help="Backend application layer protocol (default: echo)",
    )

    # ---- CLIENT SUBCOMMAND ----
    cli_parser = subparsers.add_parser(
        "client",
        parents=[root_parser],
        help="Run SSL Tunnel Client connection node",
    )
    cli_parser.add_argument(
        "server",
        help="Server address in host:port format (e.g. 127.0.0.1:18443)",
    )
    cli_parser.add_argument(
        "--client-id",
        default="0.0.0.0",
        help="Custom client identity address A.B.C.D (default: 0.0.0.0 for auto-assign)",
    )
    cli_parser.add_argument(
        "--ssl-mode",
        default="secure",
        choices=["insecure", "trusted", "secure"],
        help="SSL verification level: insecure (trust all), trusted (hash matching), secure (ca chain) (default: secure)",
    )
    cli_parser.add_argument(
        "--fingerprint",
        default=None,
        help="Hex-encoded SHA-256 fingerprint of the server certificate for 'trusted' SSL verification",
    )

    # Backend specification for Client
    cli_backend_group = cli_parser.add_argument_group("Client Backend Configurations")
    cli_backend_group.add_argument(
        "--backend",
        default="echo",
        choices=["echo"],
        help="Backend application layer protocol (default: echo)",
    )
    cli_backend_group.add_argument(
        "--packet-type-filter",
        default=0,
        type=int,
        choices=[0, 4, 6],
        help="For echo backend: If not 0, filter response, sending back only packet types given (default: 0)",
    )

    return main_parser


def main(args_list: Optional[List[str]] = None) -> None:
    """The main entry point parsed by setuptools scripts."""
    parser = get_cli_parser()
    parsed_args = parser.parse_args(args_list)

    padding_int = PADDING_STR_MAP[parsed_args.padding]

    if parsed_args.command == "server":
        server_instance = TunnelServer(
            bind=parsed_args.bind,
            port=parsed_args.port,
            pem_path=parsed_args.pem,
            padding_mode=padding_int,
            sync_timeout=parsed_args.timeout,
            console_level=parsed_args.console_level,
            logfile=parsed_args.logfile,
            file_level=parsed_args.file_level,
        )
        try:
            asyncio.run(server_instance.start())
        except KeyboardInterrupt:
            server_instance.stop()
            print("\nServer gracefully shut down.")

    elif parsed_args.command == "client":
        if ":" not in parsed_args.server:
            print("Error: Server address must be in host:port format (e.g., 127.0.0.1:18443)")
            sys.exit(1)

        host, port_str = parsed_args.server.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            print("Error: Port in server parameter must be a valid integer")
            sys.exit(1)

        try:
            cid_bytes = parse_ip_bytes(parsed_args.client_id)
        except ValueError as err:
            print(f"Error: {err}")
            sys.exit(1)

        be_opts = {
            "packet_type_filter": parsed_args.packet_type_filter,
        }

        client_instance = TunnelClient(
            host=host,
            port=port,
            requested_client_id=cid_bytes,
            padding_mode=padding_int,
            sync_timeout=parsed_args.timeout,
            backend_name=parsed_args.backend,
            backend_options=be_opts,
            ssl_mode=parsed_args.ssl_mode,
            trusted_fingerprint=parsed_args.fingerprint,
            console_level=parsed_args.console_level,
            logfile=parsed_args.logfile,
            file_level=parsed_args.file_level,
        )

        try:
            asyncio.run(client_instance.connect())
            # Maintain connection alive if run as process
            while client_instance.is_connected:
                asyncio.run(asyncio.sleep(1))
        except KeyboardInterrupt:
            asyncio.run(client_instance.disconnect())
            print("\nClient gracefully disconnected.")
        except Exception as err:
            print(f"Tunnel connection failed: {err}")
            sys.exit(1)


if __name__ == "__main__":
    main()
