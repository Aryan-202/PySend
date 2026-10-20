"""Unit tests for local interface detection and the scan command."""

import unittest
from unittest.mock import AsyncMock, Mock, patch

from click.testing import CliRunner

from pylan.cli.scan import execute_discovery, get_local_interfaces, scan


class TestGetLocalInterfaces(unittest.TestCase):
    """Verify interface lookup and its loopback fallback."""

    def test_returns_selected_local_address_and_closes_socket(self):
        """Return the primary route address after a successful socket probe."""
        sock = Mock()
        sock.getsockname.return_value = ("192.0.2.5", 0)
        with patch("pylan.cli.scan.socket.socket", return_value=sock):
            self.assertEqual(get_local_interfaces(), ["192.0.2.5"])

        sock.connect.assert_called_once_with(("8.8.8.8", 80))
        sock.close.assert_called_once()

    def test_returns_loopback_when_interface_probe_fails(self):
        """Use loopback when the route-address probe raises an OS error."""
        sock = Mock()
        sock.connect.side_effect = OSError("no route")
        with patch("pylan.cli.scan.socket.socket", return_value=sock):
            self.assertEqual(get_local_interfaces(), ["127.0.0.1"])

        sock.close.assert_called_once()


class TestExecuteDiscovery(unittest.IsolatedAsyncioTestCase):
    """Verify discovery initialization and forwarding of scanner results."""

    async def test_uses_local_interfaces_and_returns_discovered_devices(self):
        """Pass the detected interfaces and timeout into staged discovery."""
        devices = [Mock()]
        engine = Mock()
        engine.discover_staged = AsyncMock(return_value=devices)

        with (
            patch(
                "pylan.cli.scan.DiscoveryEngine", return_value=engine
            ) as factory,
            patch(
                "pylan.cli.scan.get_local_interfaces",
                return_value=["192.0.2.5"],
            ),
            patch("pylan.cli.scan.socket.gethostname", return_value="host"),
            patch("pylan.cli.scan.uuid.uuid4") as uuid4,
        ):
            uuid4.return_value.hex = "0123456789abcdef"
            result = await execute_discovery(1.5)

        factory.assert_called_once_with(
            alias="host",
            fingerprint="0123456789ab",
            tcp_port=44000,
            device_model="CLI Scanner",
        )
        engine.discover_staged.assert_awaited_once_with(
            interface_ips=["192.0.2.5"], grace_period=1.5
        )
        self.assertIs(result, devices)


class TestScanCommand(unittest.TestCase):
    """Verify user-visible results and failures from the scan command."""

    def test_no_devices_reports_empty_result(self):
        """Print a clear message when discovery returns no peers."""
        with patch(
            "pylan.cli.scan.execute_discovery",
            new=AsyncMock(return_value=[]),
        ):
            result = CliRunner().invoke(scan, [])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("No PyLan devices found", result.output)

    def test_devices_are_formatted_for_display(self):
        """Display discovered identity and address values in the result table.

        The scan command supports both wrapped and direct device records.
        """
        device = Mock()
        device.device.alias = "Laptop"
        device.device.fingerprint = "fingerprint-1"
        device.device.channel.host = "192.0.2.8"

        with patch(
            "pylan.cli.scan.execute_discovery",
            new=AsyncMock(return_value=[device]),
        ):
            result = CliRunner().invoke(scan, ["--timeout", "0.5"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("ALIAS / NAME", result.output)
        self.assertIn("Laptop", result.output)
        self.assertIn("fingerprint-1", result.output)
        self.assertIn("192.0.2.8", result.output)

    def test_discovery_error_exits_with_message(self):
        """Report staged discovery errors using the command's error path."""
        with patch(
            "pylan.cli.scan.execute_discovery",
            new=AsyncMock(side_effect=RuntimeError("scan failed")),
        ):
            result = CliRunner().invoke(scan, [])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Error scanning network: scan failed", result.output)


if __name__ == "__main__":
    unittest.main()
