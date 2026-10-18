"""Data models for PyLan discovery and node identities."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ProtocolType(str, Enum):
    TCP = "tcp"
    HTTP = "http"
    HTTPS = "https"


@dataclass(frozen=True)
class HttpChannel:
    host: str
    port: int
    protocol: ProtocolType = ProtocolType.TCP


@dataclass
class DiscoveredDevice:
    alias: str
    version: str
    device_model: Optional[str]
    device_type: str
    fingerprint: str
    channel: HttpChannel
    download: bool = True


@dataclass
class StatefulDevice:
    device: DiscoveredDevice
    first_seen: datetime
    last_seen: datetime
    channels: list[HttpChannel] = field(default_factory=list)


class DeviceStore:
    """Thread-safe and async-safe in-memory store for discovered peers."""

    def __init__(self) -> None:
        self._devices: dict[str, StatefulDevice] = {}  # keyed by fingerprint

    def upsert(self, device: DiscoveredDevice) -> tuple[bool, StatefulDevice]:
        """Insert or update a device record.

        Returns:
            A tuple of (is_new, stateful_device).
        """
        now = datetime.now()
        fp = device.fingerprint

        if fp in self._devices:
            entry = self._devices[fp]
            entry.device = device
            entry.last_seen = now
            if device.channel not in entry.channels:
                entry.channels.append(device.channel)
            return False, entry
        else:
            stateful = StatefulDevice(
                device=device,
                first_seen=now,
                last_seen=now,
                channels=[device.channel],
            )
            self._devices[fp] = stateful
            return True, stateful

    def all_devices(self) -> list[StatefulDevice]:
        return list(self._devices.values())

    def get_by_fingerprint(self, fingerprint: str) -> Optional[StatefulDevice]:
        return self._devices.get(fingerprint)
