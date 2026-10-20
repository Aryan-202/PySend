"""Send files to a discovered PyLan peer node."""

import asyncio
import json
import logging
import os

import click

from pylan.core.protocol import (
    HEADER_SIZE,
    MSG_TYPE_TRANSFER_ACCEPT,
    MSG_TYPE_TRANSFER_CHUNK,
    MSG_TYPE_TRANSFER_COMPLETE,
    MSG_TYPE_TRANSFER_REJECT,
    MSG_TYPE_TRANSFER_REQUEST,
    pack_message,
    unpack_header,
)

logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024  # 64 KB per network chunk
NETWORK_TIMEOUT = 10.0  # 10s timeout for handshakes


async def execute_transfer(host: str, port: int, file_path: str) -> None:
    """Connect to receiver, negotiate transfer, and stream file contents.

    Args:
        host: Destination IP address or hostname.
        port: Destination TCP port.
        file_path: Local filesystem path to the file to transmit.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=NETWORK_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        message = f"Could not connect to {host}:{port}: {exc}"
        raise ConnectionError(message) from exc

    try:
        request_payload = {
            "file_name": file_name,
            "file_size": file_size,
        }
        writer.write(pack_message(MSG_TYPE_TRANSFER_REQUEST, request_payload))
        await writer.drain()

        header_bytes = await asyncio.wait_for(
            reader.readexactly(HEADER_SIZE),
            timeout=NETWORK_TIMEOUT,
        )
        msg_type, length = unpack_header(header_bytes)
        body = await asyncio.wait_for(
            reader.readexactly(length),
            timeout=NETWORK_TIMEOUT,
        )

        if msg_type != MSG_TYPE_TRANSFER_ACCEPT:
            if msg_type == MSG_TYPE_TRANSFER_REJECT:
                try:
                    response = json.loads(body.decode("utf-8"))
                    reason = response.get("reason", "unknown")
                except Exception:
                    reason = "rejected by receiver"
                click.secho(f"Transfer rejected: {reason}", fg="red")
            else:
                click.secho(f"Unexpected response code: {msg_type}", fg="red")
            return

        with open(file_path, "rb") as f, click.progressbar(
            length=file_size,
            label=f"Sending {file_name}",
        ) as bar:
            while chunk := f.read(CHUNK_SIZE):
                writer.write(pack_message(MSG_TYPE_TRANSFER_CHUNK, chunk))
                await writer.drain()
                bar.update(len(chunk))

        writer.write(pack_message(MSG_TYPE_TRANSFER_COMPLETE, {}))
        await writer.drain()

        click.secho(
            f"\nSuccessfully sent {file_name} ({file_size} bytes) "
            f"to {host}:{port}",
            fg="green",
        )

    except (asyncio.IncompleteReadError, ConnectionResetError) as exc:
        raise ConnectionError(
            "Peer disconnected prematurely during transfer."
        ) from exc
    finally:
        writer.close()
        await writer.wait_closed()


@click.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--to",
    "-t",
    "target",
    required=True,
    help="Target peer address in HOST or HOST:PORT format.",
)
def send(file: str, target: str) -> None:
    """Send a file to a remote PyLan receiver node."""
    if ":" in target:
        host, port_str = target.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            click.secho(f"Invalid port: {port_str}", fg="red", err=True)
            raise SystemExit(1)
    else:
        host, port = target, 44000

    try:
        asyncio.run(execute_transfer(host, port, file))
    except Exception as exc:
        click.secho(f"Transfer failed: {exc}", fg="red", err=True)
        raise SystemExit(1)
