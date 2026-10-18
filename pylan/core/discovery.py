"""Network discovery module implementing UDP multicast announcements and
subnet sweeps.

This module coordinates local-area network discovery for peer devices using a
hybrid approach: passive/active UDP multicast broadcasting, directed TCP
probing using custom framing protocols, and fallback concurrent /24 subnet
sweeps.
"""

import asyncio
import ipaddress
import json
import logging
import socket
from typing import Callable, Optional

from pylan.core.models import (
    DeviceStore,
    DiscoveredDevice,
    HttpChannel,
    ProtocolType,
    StatefulDevice,
)
from pylan.core.protocol import HEADER_SIZE, pack_message, unpack_header

logger = logging.getLogger(__name__)

DEFAULT_MULTICAST_GROUP = "224.0.0.167"
DEFAULT_MULTICAST_PORT = 53317
DEFAULT_DISCOVERY_TIMEOUT = 0.5
SCAN_CONCURRENCY = 50

MSG_TYPE_ANNOUNCE = 10
MSG_TYPE_PROBE_REQUEST = 11
MSG_TYPE_PROBE_RESPONSE = 12


class DiscoveryProtocol(asyncio.DatagramProtocol):
    """Asyncio datagram protocol for handling incoming UDP multicast frames.

    Decodes inbound datagram payloads as UTF-8 JSON objects and dispatches
    valid messages to the registered callback handler.
    """

    def __init__(
        self, on_message: Callable[[dict, tuple[str, int]], None]
    ) -> None:
        """Initialize the datagram protocol handler.

        Args:
            on_message: Callback function executed when a valid JSON datagram
                is parsed. Receives the decoded payload dictionary and the
                source (host, port) tuple.
        """
        self.on_message = on_message
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Invoked when the underlying datagram endpoint socket is established.

        Args:
            transport: The initialized datagram transport instance.
        """
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Process an incoming raw UDP datagram.

        Attempts to decode the packet as a UTF-8 encoded JSON object.
        Malformatted packets are suppressed and logged at debug severity.

        Args:
            data: Raw packet bytes received from the network socket.
            addr: Source network address represented as a (host, port) tuple.
        """
        try:
            payload = json.loads(data.decode("utf-8"))
            self.on_message(payload, addr)
        except Exception as e:
            logger.debug(
                "Failed to decode multicast packet from %s: %s", addr, e
            )


class DiscoveryEngine:
    """Orchestrates network peer discovery, registration, and health sweeps.

    Provides high-level coordination between multicast broadcasting, inbound
    datagram listening, framed TCP probing handshakes, and parallel subnet
    port sweeps.
    """

    def __init__(
        self,
        alias: str,
        fingerprint: str,
        tcp_port: int,
        device_type: str = "desktop",
        device_model: Optional[str] = None,
        multicast_group: str = DEFAULT_MULTICAST_GROUP,
        multicast_port: int = DEFAULT_MULTICAST_PORT,
        timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    ) -> None:
        """Initialize the discovery engine with local identity and network
        parameters.

        Args:
            alias: Human-readable display name of this node.
            fingerprint: Unique persistent identifier for this host instance.
            tcp_port: Port where the local TCP framing service listens.
            device_type: Form factor category (e.g., 'desktop', 'mobile').
            device_model: Hardware or platform model identifier.
            multicast_group: IPv4 multicast address used for group
                announcements.
            multicast_port: UDP port assigned for multicast traffic.
            timeout: Network socket timeout in seconds for handshake
                operations.
        """
        self.alias = alias
        self.fingerprint = fingerprint
        self.tcp_port = tcp_port
        self.device_type = device_type
        self.device_model = device_model
        self.multicast_group = multicast_group
        self.multicast_port = multicast_port
        self.timeout = timeout

        self.store = DeviceStore()
        self.is_scanning = False
        self._active_subnet_scans: set[str] = set()

    def get_announcement_payload(self) -> dict:
        """Generate the standard announcement metadata dictionary for the node.

        Returns:
            Dictionary containing node identity, version, communication port,
            supported protocols, and operational capabilities.
        """
        return {
            "alias": self.alias,
            "version": "0.0.2",
            "device_model": self.device_model,
            "device_type": self.device_type,
            "fingerprint": self.fingerprint,
            "port": self.tcp_port,
            "protocol": ProtocolType.TCP.value,
            "download": True,
        }

    async def start_multicast_listener(
        self,
    ) -> Optional[asyncio.DatagramTransport]:
        """Configure and bind an asynchronous UDP multicast receiver socket.

        Configures address/port reuse flags, joins the specified multicast
        IGMP group across all local interfaces, and registers an asyncio
        datagram endpoint.

        Returns:
            The active DatagramTransport if binding succeeds; None if socket
            configuration or membership join fails.
        """
        loop = asyncio.get_running_loop()
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", self.multicast_port))

            mreq = socket.inet_aton(self.multicast_group) + socket.inet_aton(
                "0.0.0.0"
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.setblocking(False)

            transport, _ = await loop.create_datagram_endpoint(
                lambda: DiscoveryProtocol(self._on_multicast_received),
                sock=sock,
            )
            logger.info(
                "Multicast listener active on %s:%d",
                self.multicast_group,
                self.multicast_port,
            )
            return transport
        except Exception as e:
            logger.warning(
                "Could not bind multicast socket (%s). "
                "Continuing in fallback mode.",
                e,
            )
            return None

    def _on_multicast_received(
        self,
        data: dict,
        addr: tuple[str, int],
    ) -> None:
        """Handle incoming multicast discovery packets from peer devices.

        Filters out self-announcements and dispatches an asynchronous direct
        TCP probe task against the advertising peer.

        Args:
            data: Decoded JSON dictionary transmitted by the peer.
            addr: Source address tuple containing (ip_address,
                ephemeral_port).
        """
        peer_fp = data.get("fingerprint")
        if not peer_fp or peer_fp == self.fingerprint:
            return

        peer_host = addr[0]
        peer_port = data.get("port", self.tcp_port)
        asyncio.create_task(self.probe(peer_host, peer_port))

    async def announce(self) -> None:
        """Transmit a UDP multicast announcement datagram to the local subnet.

        Constructs a transient datagram socket with a time-to-live (TTL) of 2
        and broadcasts this node's registration payload to the designated
        multicast group and port.
        """
        payload = json.dumps(self.get_announcement_payload()).encode("utf-8")
        sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            sock.sendto(payload, (self.multicast_group, self.multicast_port))
        finally:
            sock.close()

    async def probe(self, host: str, port: int) -> Optional[StatefulDevice]:
        """Perform a framed TCP discovery handshake with a network endpoint.

        Connects over TCP, sends an envelope-wrapped registration request,
        reads and unpacks the fixed-length protocol header, retrieves the
        response body, and updates the local device registry upon a valid
        handshake.

        Args:
            host: Destination IPv4 or hostname string.
            port: Destination TCP service port.

        Returns:
            The upserted StatefulDevice instance if the handshake and device
            registration succeed; None if connection fails, times out, or the
            peer matches self.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
        except (OSError, asyncio.TimeoutError):
            return None

        try:
            request_data = pack_message(
                MSG_TYPE_PROBE_REQUEST, self.get_announcement_payload()
            )
            writer.write(request_data)
            await writer.drain()

            header_bytes = await asyncio.wait_for(
                reader.readexactly(HEADER_SIZE), timeout=self.timeout
            )
            msg_type, length = unpack_header(header_bytes)

            body_bytes = await asyncio.wait_for(
                reader.readexactly(length), timeout=self.timeout
            )
            response = json.loads(body_bytes.decode("utf-8"))

            peer_fp = response.get("fingerprint")
            if not peer_fp or peer_fp == self.fingerprint:
                return None

            device = DiscoveredDevice(
                alias=response.get("alias", "Unknown"),
                version=response.get("version", "0.0.1"),
                device_model=response.get("device_model"),
                device_type=response.get("device_type", "desktop"),
                fingerprint=peer_fp,
                channel=HttpChannel(
                    host=host, port=port, protocol=ProtocolType.TCP
                ),
                download=response.get("download", True),
            )

            is_new, stateful = self.store.upsert(device)
            logger.info(
                "Discovered device: %s at %s:%d (New: %s)",
                device.alias,
                host,
                port,
                is_new,
            )
            return stateful
        except Exception as e:
            logger.debug(
                "Failed probe handshake with %s:%d: %s", host, port, e
            )
            return None
        finally:
            writer.close()
            await writer.wait_closed()

    async def scan_subnet(
        self, interface_ip: str, port: Optional[int] = None
    ) -> list[StatefulDevice]:
        """Perform a concurrent probe sweep across an entire /24 IPv4 subnet.

        Calculates host addresses within the interface's /24 block and
        dispatches TCP probe attempts throttled by an asynchronous
        concurrency semaphore.

        Args:
            interface_ip: The local interface IP address defining the /24
                network.
            port: Target TCP port to probe. Defaults to this node's tcp_port.

        Returns:
            A list of successfully discovered and registered
            StatefulDevice instances. Returns an empty list if a scan on the
            given interface is already running.
        """
        target_port = port or self.tcp_port
        network = ipaddress.ip_network(f"{interface_ip}/24", strict=False)

        if interface_ip in self._active_subnet_scans:
            return []

        self._active_subnet_scans.add(interface_ip)
        semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)

        async def _bounded_probe(ip_str: str) -> Optional[StatefulDevice]:
            if ip_str == interface_ip:
                return None
            async with semaphore:
                return await self.probe(ip_str, target_port)

        try:
            tasks = [_bounded_probe(str(ip)) for ip in network.hosts()]
            results = await asyncio.gather(*tasks)
            return [d for d in results if d is not None]
        finally:
            self._active_subnet_scans.discard(interface_ip)

    async def discover_staged(
        self,
        interface_ips: list[str],
        known_channels: Optional[list[HttpChannel]] = None,
        grace_period: float = 1.0,
    ) -> list[StatefulDevice]:
        """Execute a staged discovery pipeline with escalation fallbacks.

        The discovery progression operates as follows:
        1. Broadcasts an initial UDP multicast announcement.
        2. Probes pre-existing or cached endpoint channels concurrently.
        3. Sleeps for a grace period to collect passive responses.
        4. If no new devices are registered, escalates to a full /24 subnet
           sweep across all supplied interface addresses.

        Args:
            interface_ips: List of local interface IPv4 strings for subnet
                sweeps.
            known_channels: Optional collection of previously discovered or
                favorited communication channels to target immediately.
            grace_period: Time in seconds to wait for initial responses before
                initiating full subnet scans.

        Returns:
            A consolidated list of all known active devices currently in the
            store.
        """
        known_channels = known_channels or []
        count_before = len(self.store.all_devices())

        await self.announce()
        probe_tasks = [self.probe(ch.host, ch.port) for ch in known_channels]
        if probe_tasks:
            await asyncio.gather(*probe_tasks)

        await asyncio.sleep(grace_period)

        if len(self.store.all_devices()) == count_before:
            logger.info(
                "No peers discovered via multicast/favorites. "
                "Escalating to subnet sweep..."
            )
            scan_tasks = [self.scan_subnet(ip) for ip in interface_ips]
            await asyncio.gather(*scan_tasks)

        return self.store.all_devices()
