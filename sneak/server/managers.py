"""Manages active WebSocket-like TCP connections and message broadcasting."""

import asyncio
from typing import Optional
from asyncio import StreamWriter


class ConnectionManager:
    """Tracks active client writers and handles broadcast delivery.

    Uses an asyncio Lock to safely handle concurrent connect/disconnect
    events. Automatically removes dead connections on broadcast failure.
    """

    def __init__(self):
        self._connections: dict[str, StreamWriter] = {}
        self._lock = asyncio.Lock()

    async def connect(self, user_id: str, writer: StreamWriter) -> None:
        async with self._lock:
            self._connections[user_id] = writer

    async def disconnect(self, user_id: str) -> None:
        async with self._lock:
            self._connections.pop(user_id, None)

    async def broadcast(
        self, message: str, exclude_user: Optional[str] = None
    ) -> None:
        """Send a newline-delimited JSON message to all connected clients.

        Silently removes any connections that fail during write.
        """
        data = (message + "\n").encode()
        async with self._lock:
            dead: list[str] = []
            for user_id, writer in self._connections.items():
                if user_id == exclude_user:
                    continue
                try:
                    writer.write(data)
                    await writer.drain()
                except Exception:
                    dead.append(user_id)

            for user_id in dead:
                self._connections.pop(user_id, None)

    async def send_to(self, user_id: str, message: str) -> bool:
        """Send a message to a specific user. Returns True on success."""
        data = (message + "\n").encode()
        async with self._lock:
            if writer := self._connections.get(user_id):
                try:
                    writer.write(data)
                    await writer.drain()
                    return True
                except Exception:
                    return False
        return False
