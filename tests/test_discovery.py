"""Tests for UDP and TCP peer discovery behavior.

The tests isolate network operations with mocks so that discovery parsing,
registration, scan coordination, and fallback decisions are deterministic
and do not require a live network.
"""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, Mock, call, patch

from pylan.core.discovery import (
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_MULTICAST_GROUP,
    DEFAULT_MULTICAST_PORT,
    MSG_TYPE_PROBE_REQUEST,
    SCAN_CONCURRENCY,
    DiscoveryEngine,
    DiscoveryProtocol,
)
from pylan.core.models import (
    DiscoveredDevice,
    HttpChannel,
    ProtocolType,
)
from pylan.core.protocol import pack_message


def make_response(fingerprint="peer-fingerprint", **overrides):
    """Create a standard peer payload for probe-response tests."""
    response = {
        "alias": "Peer",
        "version": "1.2.3",
        "device_model": "Model X",
        "device_type": "desktop",
        "fingerprint": fingerprint,
        "download": True,
    }
    response.update(overrides)
    return response


class TestDiscoveryProtocol(unittest.TestCase):
    """Verify decoding and dispatch behavior for inbound UDP datagrams."""

    def test_valid_json_is_dispatched_with_source_address(self):
        """Pass decoded JSON and the sender address to the callback."""
        callback = Mock()
        protocol = DiscoveryProtocol(callback)
        payload = {"fingerprint": "peer"}
        address = ("192.0.2.10", 53317)

        protocol.datagram_received(json.dumps(payload).encode(), address)

        callback.assert_called_once_with(payload, address)

    def test_malformed_datagram_does_not_escape_callback(self):
        """Ignore invalid encodings and JSON without invoking the callback."""
        callback = Mock()
        protocol = DiscoveryProtocol(callback)

        protocol.datagram_received(b"\xff", ("192.0.2.10", 53317))
        protocol.datagram_received(b"{invalid", ("192.0.2.10", 53317))

        callback.assert_not_called()

    def test_callback_exception_is_suppressed(self):
        """Log and suppress callback failures raised while dispatching."""
        callback = Mock(side_effect=RuntimeError("callback failed"))
        protocol = DiscoveryProtocol(callback)

        protocol.datagram_received(b"{}", ("192.0.2.10", 53317))

        callback.assert_called_once()


class TestDiscoveryEngine(unittest.TestCase):
    """Verify engine defaults and construction of its announcement payload."""

    def test_defaults_and_announcement_payload(self):
        """Expose configured identity, transport, and capability metadata."""
        engine = DiscoveryEngine(
            alias="Workstation",
            fingerprint="local-fingerprint",
            tcp_port=44000,
            device_model="Model Y",
        )

        self.assertEqual(engine.multicast_group, DEFAULT_MULTICAST_GROUP)
        self.assertEqual(engine.multicast_port, DEFAULT_MULTICAST_PORT)
        self.assertEqual(engine.timeout, DEFAULT_DISCOVERY_TIMEOUT)
        self.assertFalse(engine.is_scanning)
        self.assertEqual(engine.store.all_devices(), [])
        self.assertEqual(
            engine.get_announcement_payload(),
            {
                "alias": "Workstation",
                "version": "0.0.2",
                "device_model": "Model Y",
                "device_type": "desktop",
                "fingerprint": "local-fingerprint",
                "port": 44000,
                "protocol": ProtocolType.TCP.value,
                "download": True,
            },
        )


class TestDiscoveryEngineAsync(unittest.IsolatedAsyncioTestCase):
    """Exercise asynchronous network discovery without real network access."""

    def setUp(self):
        """Create an engine with stable local identity for each test."""
        self.engine = DiscoveryEngine(
            alias="Local",
            fingerprint="local-fingerprint",
            tcp_port=44000,
            timeout=0.1,
        )

    @staticmethod
    def make_writer():
        """Create a mock stream writer supporting the probe lifecycle."""
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return writer

    async def test_announce_sends_json_and_closes_socket(self):
        """Send the expected payload to the configured multicast endpoint."""
        sock = Mock()
        with patch("pylan.core.discovery.socket.socket", return_value=sock):
            await self.engine.announce()

        sent_payload, destination = sock.sendto.call_args.args
        self.assertEqual(
            destination,
            (DEFAULT_MULTICAST_GROUP, DEFAULT_MULTICAST_PORT),
        )
        self.assertEqual(
            json.loads(sent_payload.decode("utf-8")),
            self.engine.get_announcement_payload(),
        )
        sock.close.assert_called_once()

    async def test_probe_registers_peer_and_closes_writer(self):
        """Decode a framed response and store the identified remote peer."""
        response = make_response()
        response_bytes = pack_message(12, response)
        reader = asyncio.StreamReader()
        reader.feed_data(response_bytes)
        reader.feed_eof()
        writer = self.make_writer()
        with patch(
            "pylan.core.discovery.asyncio.open_connection",
            new=AsyncMock(return_value=(reader, writer)),
        ) as open_connection:
            device = await self.engine.probe("192.0.2.10", 44001)

        self.assertIsNotNone(device)
        self.assertEqual(device.device.fingerprint, "peer-fingerprint")
        self.assertEqual(device.device.alias, "Peer")
        self.assertEqual(
            device.device.channel,
            HttpChannel("192.0.2.10", 44001, ProtocolType.TCP),
        )
        self.assertEqual(len(self.engine.store.all_devices()), 1)
        open_connection.assert_awaited_once_with("192.0.2.10", 44001)
        self.assertEqual(
            writer.write.call_args.args[0][0], MSG_TYPE_PROBE_REQUEST
        )
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_probe_ignores_response_for_self(self):
        """Do not register a response that carries the local fingerprint."""
        reader = asyncio.StreamReader()
        reader.feed_data(
            pack_message(
                12, make_response(fingerprint=self.engine.fingerprint)
            )
        )
        reader.feed_eof()
        writer = self.make_writer()
        with patch(
            "pylan.core.discovery.asyncio.open_connection",
            new=AsyncMock(return_value=(reader, writer)),
        ):
            result = await self.engine.probe("192.0.2.10", 44001)

        self.assertIsNone(result)
        self.assertEqual(self.engine.store.all_devices(), [])
        writer.wait_closed.assert_awaited_once()

    async def test_probe_returns_none_when_connection_fails(self):
        """Treat an unavailable endpoint as an unsuccessful probe."""
        with patch(
            "pylan.core.discovery.asyncio.open_connection",
            new=AsyncMock(side_effect=OSError("connection refused")),
        ):
            result = await self.engine.probe("192.0.2.10", 44001)

        self.assertIsNone(result)

    async def test_scan_subnet_probes_other_hosts_and_uses_port(self):
        """Probe the /24 hosts except the local address and retain matches."""
        discovered = Mock()
        active_probes = 0
        peak_concurrency = 0

        async def probe(host, port):
            nonlocal active_probes, peak_concurrency
            self.assertEqual(port, 44001)
            active_probes += 1
            peak_concurrency = max(peak_concurrency, active_probes)
            await asyncio.sleep(0)
            active_probes -= 1
            return discovered if host.endswith(".2") else None

        with patch.object(
            self.engine, "probe", side_effect=probe
        ) as probe_mock:
            results = await self.engine.scan_subnet(
                "192.0.2.1", port=44001
            )

        self.assertEqual(results, [discovered])
        self.assertEqual(probe_mock.await_count, 253)
        self.assertNotIn(
            call("192.0.2.1", 44001), probe_mock.await_args_list
        )
        self.assertIn(
            call("192.0.2.2", 44001), probe_mock.await_args_list
        )
        self.assertLessEqual(peak_concurrency, SCAN_CONCURRENCY)
        self.assertEqual(self.engine._active_subnet_scans, set())

    async def test_scan_subnet_skips_an_active_scan(self):
        """Avoid starting a second concurrent sweep for the same interface."""
        entered_probe = asyncio.Event()
        release_probe = asyncio.Event()

        async def blocked_probe(_host, _port):
            self.assertNotEqual(_host, "192.0.2.1")
            self.assertEqual(_port, 44000)
            entered_probe.set()
            await release_probe.wait()
            return None

        with patch.object(self.engine, "probe", side_effect=blocked_probe):
            first_scan = asyncio.create_task(
                self.engine.scan_subnet("192.0.2.1")
            )
            await entered_probe.wait()
            second_result = await self.engine.scan_subnet("192.0.2.1")
            release_probe.set()
            await first_scan

        self.assertEqual(second_result, [])
        self.assertEqual(self.engine._active_subnet_scans, set())

    async def test_scan_subnet_clears_lock_when_probe_raises(self):
        """Release the interface scan lock even when a probe raises."""
        with patch.object(
            self.engine,
            "probe",
            new=AsyncMock(side_effect=RuntimeError("probe failed")),
        ):
            with self.assertRaises(RuntimeError):
                await self.engine.scan_subnet("192.0.2.1")

        self.assertEqual(self.engine._active_subnet_scans, set())

    async def test_discover_staged_skips_sweep_after_finding_peer(self):
        """Avoid subnet scans when known-channel probing adds a device."""
        channel = HttpChannel("192.0.2.10", 44001)
        device = DiscoveredDevice(
            alias="Peer",
            version="1.0",
            device_model=None,
            device_type="desktop",
            fingerprint="peer-fingerprint",
            channel=channel,
        )

        async def find_peer(host, port):
            self.assertEqual((host, port), (channel.host, channel.port))
            self.engine.store.upsert(device)
            return self.engine.store.get_by_fingerprint(
                "peer-fingerprint"
            )

        with (
            patch.object(self.engine, "announce", new=AsyncMock()),
            patch.object(self.engine, "probe", side_effect=find_peer),
            patch.object(self.engine, "scan_subnet", new=AsyncMock()) as scan,
            patch("pylan.core.discovery.asyncio.sleep", new=AsyncMock()),
        ):
            results = await self.engine.discover_staged(
                ["192.0.2.1"], [channel], grace_period=0
            )

        self.assertEqual(len(results), 1)
        scan.assert_not_awaited()

    async def test_discover_staged_sweeps_when_no_peer_is_found(self):
        """Escalate to each configured interface after an empty first stage."""
        with (
            patch.object(self.engine, "announce", new=AsyncMock()),
            patch.object(self.engine, "scan_subnet", new=AsyncMock()) as scan,
            patch("pylan.core.discovery.asyncio.sleep", new=AsyncMock()),
        ):
            results = await self.engine.discover_staged(
                ["192.0.2.1", "198.51.100.1"], grace_period=0
            )

        self.assertEqual(results, [])
        self.assertEqual(scan.await_count, 2)
        scan.assert_any_await("192.0.2.1")
        scan.assert_any_await("198.51.100.1")


if __name__ == "__main__":
    unittest.main()
