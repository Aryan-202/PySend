"""Unit tests for receiver client handling and transfer storage."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from click.testing import CliRunner

from pylan.cli.receive import (
    handle_client,
    handle_transfer,
    periodic_announce,
    receive,
    start_receiver_daemon,
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


class TestReceiveTransfer(unittest.IsolatedAsyncioTestCase):
    """Verify accepted uploads are stored and malformed requests rejected."""

    def make_writer(self):
        """Return a stream writer mock with asynchronous lifecycle methods."""
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return writer

    async def test_writes_chunks_to_sanitized_file_name(self):
        """Store transfer chunks below the configured output directory."""
        payload = b"received contents"
        reader = asyncio.StreamReader()
        reader.feed_data(
            pack_message(MSG_TYPE_TRANSFER_CHUNK, payload)
            + pack_message(MSG_TYPE_TRANSFER_COMPLETE, {})
        )
        writer = self.make_writer()
        metadata = json.dumps(
            {"file_name": "../../received.txt"}
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as directory:
            await handle_transfer(reader, writer, metadata, directory)

            received_file = Path(directory) / "received.txt"
            self.assertEqual(received_file.read_bytes(), payload)

        response_type = unpack_header(
            writer.write.call_args.args[0][:HEADER_SIZE]
        )[0]
        self.assertEqual(response_type, MSG_TYPE_TRANSFER_ACCEPT)
        writer.drain.assert_awaited_once()

    async def test_invalid_metadata_sends_rejection(self):
        """Reject transfer metadata that is not valid JSON."""
        writer = self.make_writer()

        await handle_transfer(
            asyncio.StreamReader(),
            writer,
            b"invalid-json",
            tempfile.gettempdir(),
        )

        response = writer.write.call_args.args[0]
        response_type, response_length = unpack_header(response[:HEADER_SIZE])
        response_body = json.loads(
            response[HEADER_SIZE:HEADER_SIZE + response_length]
        )
        self.assertEqual(response_type, MSG_TYPE_TRANSFER_REJECT)
        self.assertIn("reason", response_body)
        writer.drain.assert_awaited_once()


class TestHandleClient(unittest.IsolatedAsyncioTestCase):
    """Verify dispatch and cleanup for incoming TCP client messages."""

    def make_writer(self):
        """Return a stream writer mock with asynchronous lifecycle methods."""
        writer = Mock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return writer

    async def test_probe_request_returns_announcement(self):
        """Respond to discovery probes with the engine's local metadata."""
        reader = asyncio.StreamReader()
        reader.feed_data(pack_message(11, {"alias": "peer"}))
        writer = self.make_writer()
        engine = Mock()
        engine.get_announcement_payload.return_value = {"alias": "local"}

        await handle_client(reader, writer, engine, "unused-output")

        response = writer.write.call_args.args[0]
        response_type, response_length = unpack_header(response[:HEADER_SIZE])
        self.assertEqual(response_type, 12)
        self.assertEqual(
            json.loads(response[HEADER_SIZE:HEADER_SIZE + response_length]),
            {"alias": "local"},
        )
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_transfer_request_dispatches_to_transfer_handler(self):
        """Pass the transfer body and destination to the transfer handler."""
        body = json.dumps({"file_name": "payload.txt"}).encode("utf-8")
        reader = asyncio.StreamReader()
        reader.feed_data(
            pack_message(
                MSG_TYPE_TRANSFER_REQUEST, {"file_name": "payload.txt"}
            )
        )
        writer = self.make_writer()
        engine = Mock()

        with patch(
            "pylan.cli.receive.handle_transfer", new=AsyncMock()
        ) as transfer_handler:
            await handle_client(reader, writer, engine, "downloads")

        transfer_handler.assert_awaited_once_with(
            reader, writer, body, "downloads"
        )
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_unhandled_message_closes_connection(self):
        """Close unsupported messages without writing a response."""
        reader = asyncio.StreamReader()
        reader.feed_data(pack_message(99, {}))
        writer = self.make_writer()

        await handle_client(reader, writer, Mock(), "unused-output")

        writer.write.assert_not_called()
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()


class TestReceiveCommand(unittest.TestCase):
    """Verify the receiver command reports shutdown consistently."""

    def test_keyboard_interrupt_reports_shutdown(self):
        """Print the normal stop message after the daemon is interrupted."""
        def interrupt_run(coroutine):
            # Close the coroutine because this test replaces asyncio.run.
            coroutine.close()
            raise KeyboardInterrupt

        with patch(
            "pylan.cli.receive.asyncio.run", side_effect=interrupt_run
        ):
            result = CliRunner().invoke(receive, [])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Receiver stopped.", result.output)


class TestReceiverLifecycle(unittest.IsolatedAsyncioTestCase):
    """Verify daemon failures stop background tasks and close transports."""

    async def test_periodic_announce_runs_until_cancelled(self):
        """Repeat announcements and stop the task on cancellation."""
        engine = Mock()
        engine.announce = AsyncMock()
        announce_task = asyncio.create_task(
            periodic_announce(engine, interval=0)
        )

        while engine.announce.await_count == 0:
            await asyncio.sleep(0)

        announce_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await announce_task

        self.assertGreaterEqual(engine.announce.await_count, 1)

    async def test_server_failure_cleans_up_announcement_and_transport(self):
        """Release multicast and announcement resources when serving fails."""
        transport = Mock()
        engine = Mock()
        engine.start_multicast_listener = AsyncMock(return_value=transport)
        announce_started = asyncio.Event()
        announce_stopped = asyncio.Event()
        server = Mock()
        server.__aenter__ = AsyncMock(return_value=server)
        server.__aexit__ = AsyncMock(return_value=False)
        server.serve_forever = AsyncMock(
            side_effect=RuntimeError("server failed")
        )

        async def announcement_loop(_engine, interval):
            try:
                announce_started.set()
                await asyncio.Event().wait()
            finally:
                announce_stopped.set()

        async def start_server(*_args, **_kwargs):
            # Yield once so the newly created announcement task can start.
            await asyncio.sleep(0)
            return server

        with (
            patch("pylan.cli.receive.DiscoveryEngine", return_value=engine),
            patch(
                "pylan.cli.receive.periodic_announce",
                side_effect=announcement_loop,
            ),
            patch(
                "pylan.cli.receive.asyncio.start_server",
                new=AsyncMock(side_effect=start_server),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "server failed"):
                await start_receiver_daemon(44000, "downloads")

        self.assertTrue(announce_started.is_set())
        self.assertTrue(announce_stopped.is_set())
        server.__aexit__.assert_awaited_once()
        transport.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
