"""Peer discovery scanner CLI for the PyLan local network transfer system.

This module provides the command-line interface and orchestration for scanning
the local network area to identify active PyLan nodes via multicast responses
and subnet TCP sweeps.
"""

import asyncio
import logging
import socket
import uuid

import click

from pylan.core.discovery import DiscoveryEngine
from pylan.core.models import StatefulDevice

logger = logging.getLogger(__name__)


def get_local_interfaces() -> list[str]:
    """Retrieve active local IPv4 outbound network addresses.

    Creates a transient UDP socket directed at an external routing target to
    reliably determine the machine's primary local IP address without sending
    actual network traffic.

    Returns:
        A list containing the local IPv4 address string, or ['127.0.0.1']
        if network interfaces cannot be probed.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return [sock.getsockname()[0]]
    except OSError:
        return ["127.0.0.1"]
    finally:
        sock.close()


async def execute_discovery(timeout: float) -> list[StatefulDevice]:
    """Initialize the discovery engine and execute staged peer sweeps.

    Configures a transient scanner engine identity, queries local routing
    interfaces, and runs the discovery progression across multicast and
    fallback subnet probes.

    Args:
        timeout: Grace period in seconds to wait for peer responses.

    Returns:
        A list of StatefulDevice instances discovered across all stages.
    """
    engine = DiscoveryEngine(
        alias=socket.gethostname(),
        fingerprint=uuid.uuid4().hex[:12],
        tcp_port=44000,
        device_model="CLI Scanner",
    )

    local_ips = get_local_interfaces()
    devices = await engine.discover_staged(
        interface_ips=local_ips,
        grace_period=timeout,
    )
    return devices


@click.command()
@click.option(
    "--timeout",
    "-t",
    default=2.0,
    type=float,
    help="Duration in seconds to wait for peer responses.",
)
def scan(timeout: float) -> None:
    """Scan the local area network for active PyLan devices."""
    click.echo(f"Scanning local network (timeout: {timeout}s)...")

    try:
        devices = asyncio.run(execute_discovery(timeout))
    except Exception as exc:
        click.secho(f"Error scanning network: {exc}", fg="red", err=True)
        raise SystemExit(1)

    if not devices:
        click.echo("No PyLan devices found on the local network.")
        return

    click.echo()
    header = f"{'ALIAS / NAME':<22} {'FINGERPRINT':<18} {'ADDRESS':<16}"
    click.secho(header, bold=True)
    click.echo("-" * 58)

    for item in devices:
        dev = getattr(item, "device", item)
        alias = getattr(dev, "alias", "Unknown")
        fingerprint = getattr(dev, "fingerprint", "N/A")
        channel = getattr(dev, "channel", None)
        address = (
            getattr(channel, "host", "Unknown") if channel else "Unknown"
        )

        click.echo(
            f"{str(alias):<22} {str(fingerprint):<18} {str(address):<16}"
        )
