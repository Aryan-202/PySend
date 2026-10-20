"""Receiver daemon for the PyLan local network transfer system.

This module provides the core listener service for incoming discovery
handshakes and file transfers. It initializes a persistent TCP server to
handle probe requests and coordinates periodic multicast announcements to
ensure active visibility to scanning peers across the local subnet.
"""

import asyncio
import json
import logging
import socket
from pathlib import Path

import click

from pylan.core.discovery import (
    DiscoveryEngine,
    MSG_TYPE_PROBE_REQUEST,
    MSG_TYPE_PROBE_RESPONSE,
)
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


async def handle_transfer(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    initial_body: bytes,
    output_dir: str,
) -> None:
    """Handle incoming file transfer stream."""
    try:
        meta = json.loads(initial_body.decode("utf-8"))
        raw_name = meta.get("file_name", "unnamed_transfer")

        safe_name = Path(raw_name).name
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / safe_name

        writer.write(pack_message(MSG_TYPE_TRANSFER_ACCEPT, {}))
        await writer.drain()

        with open(target_path, "wb") as out_file:
            while True:
                header_bytes = await reader.readexactly(HEADER_SIZE)
                msg_type, length = unpack_header(header_bytes)
                body = await reader.readexactly(length)

                if msg_type == MSG_TYPE_TRANSFER_CHUNK:
                    out_file.write(body)
                elif msg_type == MSG_TYPE_TRANSFER_COMPLETE:
                    break
                else:
                    logger.warning(
                        "Unexpected transfer chunk type: %d", msg_type
                    )
                    return

        click.secho(
            f"\nReceived file '{safe_name}' -> {target_path}", fg="green"
        )

    except Exception as exc:
        logger.debug("Transfer failed or was rejected: %s", exc)
        try:
            reject = pack_message(
                MSG_TYPE_TRANSFER_REJECT, {"reason": str(exc)}
            )
            writer.write(reject)
            await writer.drain()
        except Exception:
            pass


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    engine: DiscoveryEngine,
    output_dir: str,
) -> None:
    """Process incoming framed TCP connections from remote PyLan nodes.

    Reads and validates binary protocol headers, parses corresponding payload
    bodies, and responds to discovery probes. Non-probe payloads and connection
    errors are logged and cleanly closed without interrupting the server.

    Args:
        reader: Async stream reader connected to the incoming client socket.
        writer: Async stream writer connected to the incoming client socket.
        engine: DiscoveryEngine instance representing this local peer.
        output_dir: Filesystem path configured to store accepted transfers.
    """
    _ = output_dir  # Reserved for incoming transfer file sinks
    try:
        header_bytes = await reader.readexactly(HEADER_SIZE)
        msg_type, length = unpack_header(header_bytes)
        body = await reader.readexactly(length)

        if msg_type == MSG_TYPE_PROBE_REQUEST:
            try:
                peer_data = json.loads(body.decode("utf-8"))
                logger.debug(
                    "Received probe request from %s",
                    peer_data.get("alias", "unknown"),
                )
            except Exception as exc:
                logger.debug("Failed to decode probe payload: %s", exc)

            response_payload = engine.get_announcement_payload()
            reply = pack_message(MSG_TYPE_PROBE_RESPONSE, response_payload)
            writer.write(reply)
            await writer.drain()
        elif msg_type == MSG_TYPE_TRANSFER_REQUEST:
            await handle_transfer(reader, writer, body, output_dir)
        else:
            logger.debug("Received unhandled message type: %d", msg_type)
    except (asyncio.IncompleteReadError, ConnectionResetError) as exc:
        logger.debug("Peer disconnected unexpectedly: %s", exc)
    except Exception as exc:
        logger.debug("Error while handling client connection: %s", exc)
    finally:
        writer.close()
        await writer.wait_closed()


async def periodic_announce(
    engine: DiscoveryEngine,
    interval: float = 1.0,
) -> None:
    """Periodically broadcast multicast UDP announcements across the LAN.

    Maintains an active presence on the local subnet by continuously invoking
    multicast transmission at regular intervals. Runs until explicitly
    cancelled during daemon shutdown.

    Args:
        engine: DiscoveryEngine instance providing identity and announcements.
        interval: Delay in seconds between consecutive multicast transmissions.
    """
    while True:
        try:
            await engine.announce()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.debug("Multicast announcement broadcast failed: %s", exc)
        await asyncio.sleep(interval)


async def start_receiver_daemon(port: int, output_dir: str) -> None:
    """Start and supervise the PyLan receiver daemon lifecycle.

    Binds the local TCP framing listener, joins the discovery multicast
    group, and supervises the periodic announcement background task until
    interrupted. Ensures transports and tasks are terminated cleanly.

    Args:
        port: TCP port where incoming transfer connections will be accepted.
        output_dir: Destination directory path for storing received data.
    """
    engine = DiscoveryEngine(
        alias=socket.gethostname(),
        fingerprint="receiver-node",
        tcp_port=port,
        device_model="PyLan Desktop Node",
    )

    click.echo(f"Device alias : {socket.gethostname()}")
    click.echo(f"Listening on : port {port}")
    click.echo(f"Saving files : {output_dir}")
    click.echo(
        "Ready. Waiting for incoming discovery and file transfers "
        "(Ctrl+C to stop)..."
    )

    transport = await engine.start_multicast_listener()
    announce_task = asyncio.create_task(
        periodic_announce(engine, interval=1.0)
    )

    try:
        server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, engine, output_dir),
            host="0.0.0.0",
            port=port,
        )
        async with server:
            await server.serve_forever()
    finally:
        announce_task.cancel()
        try:
            await announce_task
        except asyncio.CancelledError:
            pass

        if transport is not None:
            transport.close()


@click.command()
@click.option(
    "-p",
    "--port",
    default=44000,
    type=int,
    help="Port to listen for incoming connections.",
)
@click.option(
    "-o",
    "--output",
    default="./downloads",
    type=click.Path(),
    help="Target folder where received files will be written.",
)
def receive(port: int, output: str) -> None:
    """Start PyLan in receiver mode to listen for peers and incoming files."""
    try:
        asyncio.run(start_receiver_daemon(port, output))
    except KeyboardInterrupt:
        click.echo("\nReceiver stopped.")
