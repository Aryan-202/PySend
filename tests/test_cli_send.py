"""Unit tests for the send command and asynchronous file transfer helper."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, call, patch

from click.testing import CliRunner

from pylan.cli.send import CHUNK_SIZE, execute_transfer, send
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


class TestExecuteTransfer(unittest.IsolatedAsyncioTestCase):
    """Verify transfer framing, errors, and connection cleanup."""

    def make_writer(self):
        """Return a stream writer mock with asynchronous lifecycle methods."""
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return writer

    async def test_sends_file_in_chunks_and_closes_connection(self):
        """Send metadata, bounded chunks, and a completion frame."""
        content = b"x" * (CHUNK_SIZE + 3)
        reader = asyncio.StreamReader()
        reader.feed_data(pack_message(MSG_TYPE_TRANSFER_ACCEPT, {}))
        writer = self.make_writer()

        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "payload.bin"
            file_path.write_bytes(content)
            with (
                patch(
                    "pylan.cli.send.asyncio.open_connection",
                    new=AsyncMock(return_value=(reader, writer)),
                ) as open_connection,
                patch("pylan.cli.send.click.secho") as secho,
            ):
                await execute_transfer("192.0.2.5", 44000, str(file_path))

        frames = [call.args[0] for call in writer.write.call_args_list]
        message_types = [
            unpack_header(frame[:HEADER_SIZE])[0] for frame in frames
        ]
        self.assertEqual(
            message_types,
            [
                MSG_TYPE_TRANSFER_REQUEST,
                MSG_TYPE_TRANSFER_CHUNK,
                MSG_TYPE_TRANSFER_CHUNK,
                MSG_TYPE_TRANSFER_COMPLETE,
            ],
        )

        request_size = unpack_header(frames[0][:HEADER_SIZE])[1]
        request = json.loads(
            frames[0][HEADER_SIZE:HEADER_SIZE + request_size]
        )
        self.assertEqual(
            request,
            {"file_name": "payload.bin", "file_size": len(content)},
        )
        self.assertEqual(
            b"".join(frame[HEADER_SIZE:] for frame in frames[1:3]),
            content,
        )
        open_connection.assert_awaited_once_with("192.0.2.5", 44000)
        self.assertEqual(writer.drain.await_count, 4)
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()
        secho.assert_called_once()

    async def test_missing_file_fails_before_connecting(self):
        """Reject paths that do not identify a regular file."""
        with patch(
            "pylan.cli.send.asyncio.open_connection"
        ) as open_connection:
            with self.assertRaises(FileNotFoundError):
                await execute_transfer("192.0.2.5", 44000, "missing-file")

        open_connection.assert_not_called()

    async def test_connection_error_is_reported(self):
        """Translate socket connection failures into a connection error."""
        with patch(
            "pylan.cli.send.asyncio.open_connection",
            new=AsyncMock(side_effect=OSError("connection refused")),
        ):
            with tempfile.NamedTemporaryFile() as file:
                with self.assertRaisesRegex(
                    ConnectionError, "Could not connect"
                ):
                    await execute_transfer("192.0.2.5", 44000, file.name)

    async def test_rejected_transfer_does_not_send_file_data(self):
        """Display the receiver's rejection and still close the stream."""
        reader = asyncio.StreamReader()
        reader.feed_data(
            pack_message(MSG_TYPE_TRANSFER_REJECT, {"reason": "not allowed"})
        )
        writer = self.make_writer()

        with tempfile.NamedTemporaryFile() as file:
            with (
                patch(
                    "pylan.cli.send.asyncio.open_connection",
                    new=AsyncMock(return_value=(reader, writer)),
                ),
                patch("pylan.cli.send.click.secho") as secho,
            ):
                await execute_transfer("192.0.2.5", 44000, file.name)

        self.assertEqual(writer.write.call_count, 1)
        secho.assert_called_once_with(
            "Transfer rejected: not allowed", fg="red"
        )
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_peer_disconnect_is_reported_and_connection_is_closed(self):
        """Raise a useful transfer error when the peer closes prematurely."""
        reader = asyncio.StreamReader()
        reader.feed_data(pack_message(MSG_TYPE_TRANSFER_ACCEPT, {}))
        writer = self.make_writer()
        writer.drain.side_effect = [None, ConnectionResetError("peer closed")]

        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "payload.bin"
            file_path.write_bytes(b"payload")
            with patch(
                "pylan.cli.send.asyncio.open_connection",
                new=AsyncMock(return_value=(reader, writer)),
            ):
                with self.assertRaisesRegex(
                    ConnectionError, "disconnected prematurely"
                ):
                    await execute_transfer(
                        "192.0.2.5", 44000, str(file_path)
                    )

        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()


class TestSendCommand(unittest.TestCase):
    """Verify command-line target parsing and error reporting."""

    def test_target_uses_default_and_explicit_ports(self):
        """Use the default receiver port unless the target specifies one."""
        with tempfile.NamedTemporaryFile() as file:
            transfer = AsyncMock()
            with patch("pylan.cli.send.execute_transfer", new=transfer):
                runner = CliRunner()
                default_result = runner.invoke(
                    send, ["--to", "192.0.2.5", file.name]
                )
                explicit_result = runner.invoke(
                    send, ["--to", "192.0.2.5:44123", file.name]
                )

        self.assertEqual(default_result.exit_code, 0)
        self.assertEqual(explicit_result.exit_code, 0)
        self.assertEqual(
            transfer.await_args_list,
            [
                call("192.0.2.5", 44000, file.name),
                call("192.0.2.5", 44123, file.name),
            ],
        )

    def test_invalid_port_exits_with_error(self):
        """Reject a non-numeric port before invoking the event loop."""
        with tempfile.NamedTemporaryFile() as file:
            result = CliRunner().invoke(
                send, ["--to", "192.0.2.5:invalid", file.name]
            )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Invalid port: invalid", result.output)

    def test_transfer_failure_exits_with_error(self):
        """Report failures raised while starting the transfer."""
        def fail_run(coroutine):
            # Close the coroutine because this test replaces asyncio.run.
            coroutine.close()
            raise RuntimeError("unexpected failure")

        with tempfile.NamedTemporaryFile() as file:
            with patch(
                "pylan.cli.send.asyncio.run",
                side_effect=fail_run,
            ):
                result = CliRunner().invoke(
                    send, ["--to", "192.0.2.5", file.name]
                )

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Transfer failed: unexpected failure", result.output)


if __name__ == "__main__":
    unittest.main()
