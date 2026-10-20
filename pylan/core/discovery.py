"""Discover peers on a local network through multicast and TCP probes.

The module provides an asyncio-based discovery protocol and engine. Peers
announce themselves over UDP multicast; the engine can also actively probe
known TCP endpoints and sweep local IPv4 /24 networks when multicast and
known endpoints do not reveal any devices. Successful probes are normalized
into :class:`DiscoveredDevice` records and stored in a :class:`DeviceStore`.

The discovery engine does not own a long-running listener lifecycle. Callers
are responsible for closing the transport returned by
:meth:`DiscoveryEngine.start_multicast_listener`.
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

    Decodes inbound datagram payloads as UTF-8 JSON and dispatches successfully
    decoded values to the registered callback. Malformed payloads and callback
    errors are logged at debug level and do not escape the event-loop callback.
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
        Malformed packets and callback errors are suppressed and logged at
        debug severity.

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
    port sweeps. Each engine owns an in-memory :class:`DeviceStore`; repeated
    discoveries of the same fingerprint update that record rather than
    creating another device.
    The engine starts without an active multicast listener or subnet scan.
    A caller may start the listener separately and close its returned
    transport when discovery is no longer needed.
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
        """Build this node's discovery metadata.

        Returns:
            A JSON-serializable dictionary containing the node alias,
            software version, optional model, device type, persistent
            fingerprint, TCP service port, protocol identifier, and download
            capability. The same payload is used in multicast announcements
            and framed TCP probe requests.
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

        Configures address/port reuse flags, binds to the configured UDP port,
        joins the specified multicast IGMP group on the default interface,
        and registers an asyncio datagram endpoint. A configuration, bind,
        membership, or endpoint-creation failure is logged and selects
        fallback discovery by returning ``None``.

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

        Filters out announcements without a fingerprint and this engine's own
        fingerprint. For other peers, it schedules a direct TCP probe to the
        packet's source host and advertised port; if the packet omits a port,
        this engine's local TCP port is used.

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

        Serializes :meth:`get_announcement_payload` as UTF-8 JSON and sends it
        using a transient IPv4 UDP socket with multicast TTL 2. The socket is
        always closed after the send attempt. Socket errors are allowed to
        propagate to the caller.
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
        reads the fixed-length protocol header and declared response body,
        then parses the body as JSON. Responses without a fingerprint or
        matching this engine's fingerprint are ignored. Valid peers are
        upserted by fingerprint, allowing their metadata and channels to be
        refreshed.

        Args:
            host: Destination IPv4 or hostname string.
            port: Destination TCP service port.

        Returns:
            The upserted ``StatefulDevice`` when the response identifies a
            peer; otherwise ``None`` when connection establishment fails,
            the response cannot be read or decoded, or the response identifies
            this engine itself.
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
            _, length = unpack_header(header_bytes)

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
        dispatches TCP probe attempts throttled by an asynchronous semaphore
        capped at :data:`SCAN_CONCURRENCY`. The interface's own address is
        skipped. Concurrent scans for the same interface are ignored, while
        scans on different interfaces can proceed independently.

        Args:
            interface_ip: Local IPv4 address identifying the subnet to scan.
            port: Destination TCP port for all probes. If omitted or falsey,
                the engine's configured TCP port is used.

        Returns:
            Successfully discovered ``StatefulDevice`` instances in subnet
            host order. Returns an empty list if a scan on the same interface
            is already running.

        Raises:
            ValueError: If ``interface_ip`` cannot be used to construct an
                IPv4 /24 network.
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
        4. If the device-store size has not changed since entry, runs a /24
           scan for each supplied interface concurrently.

        Args:
            interface_ips: Local interface IPv4 addresses to scan if initial
                discovery does not add any devices.
            known_channels: Optional collection of previously discovered or
                favorited communication channels to probe before subnet
                sweeps.
            grace_period: Time in seconds to wait for initial responses before
                deciding whether to initiate subnet scans.

        Returns:
            A snapshot of all devices currently held by this engine's store.

        Raises:
            OSError: If sending the initial multicast announcement fails.
        """
        known_channels = known_channels or []
        count_before = len(self.store.all_devices())

        transport = await self.start_multicast_listener()
        try:
            await self.announce()
            probe_tasks = [
                self.probe(ch.host, ch.port) for ch in known_channels
            ]
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
        finally:
            if transport:
                transport.close()
        return self.store.all_devices()
