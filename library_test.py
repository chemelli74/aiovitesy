# Copyright 2026 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Manual test script for the aiovitesy library."""

import asyncio
import logging
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

import orjson
from aiohttp import ClientSession
from colorlog import ColoredFormatter

from aiovitesy.api import VitesyApi
from aiovitesy.exceptions import CannotAuthenticate, CannotConnect, VitesyError


def get_arguments() -> tuple[ArgumentParser, Namespace]:
    """Parse command line arguments, optionally seeded from a JSON config file."""
    parser = ArgumentParser(description="aiovitesy library test")
    parser.add_argument("--username", "-u", type=str, help="Vitesy Hub account e-mail")
    parser.add_argument(
        "--password", "-p", type=str, help="Vitesy Hub account password"
    )
    parser.add_argument(
        "--configfile",
        "-cf",
        type=str,
        help="Load options from a JSON config file. "
        "Command line options override those in the file.",
    )

    arguments = parser.parse_args()
    if arguments.configfile and Path(arguments.configfile).exists():
        with Path(arguments.configfile).open() as config:
            arguments = parser.parse_args(
                namespace=Namespace(**orjson.loads(config.read())),
            )

    return parser, arguments


async def main() -> None:
    """Run the manual test flow."""
    parser, args = get_arguments()

    if not args.username or not args.password:
        print("You have to specify both username and password")
        parser.print_help()
        sys.exit(1)

    print("Creating HTTP ClientSession")
    session = ClientSession()

    api = VitesyApi(args.username, args.password, session)

    try:
        try:
            await api.login()
        except CannotAuthenticate:
            print("Cannot authenticate to Vitesy Hub")
            raise
        except CannotConnect:
            print("Cannot connect to Vitesy Hub")
            raise
    except VitesyError:
        await session.close()
        sys.exit(1)

    print("Logged-in.")
    print("-" * 20)

    devices = await api.get_all_devices()
    for device in devices.values():
        print(f"{'Name:':>14} {device.name}")
        print(f"{'MAC:':>14} {device.device_id}")
        print(f"{'Type:':>14} {device.device_type}")
        print(f"{'Model:':>14} {device.model}")
        print(f"{'Firmware:':>14} {device.firmware_version}")
        print(f"{'Connected:':>14} {device.connected}")
        print(f"{'Program:':>14} {device.program_id}")
        print(f"{'Measurement:':>14} {device.measurement}")
        print(f"{'Maintenance:':>14} {device.maintenance}")
        print(f"{'Programs:':>14} {device.programs}")
        print("-" * 20)

    await session.close()


def set_logging() -> None:
    """Configure colored debug logging."""
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    fmt = (
        "%(asctime)s.%(msecs)03d %(levelname)s (%(threadName)s) [%(name)s] %(message)s"
    )
    colorfmt = f"%(log_color)s{fmt}%(reset)s"
    logging.getLogger().handlers[0].setFormatter(
        ColoredFormatter(
            colorfmt,
            datefmt="%Y-%m-%d %H:%M:%S",
            reset=True,
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "red",
            },
        ),
    )


if __name__ == "__main__":
    set_logging()
    asyncio.run(main())
