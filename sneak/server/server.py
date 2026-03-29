"""
sneak server.

Handles SRP authentication and encrypted message relay over
newline-delimited JSON on raw TCP sockets.

Security properties:
  - Password never transmitted (SRP zero-knowledge proof)
  - Server stores ONLY ciphertext (cannot read messages)
  - No client IP stored in message records
  - Session key is NOT sent back to client (was a bug in v1)
"""

import asyncio
import json
import base64
import os
from dataclasses import asdict
from contextlib import suppress
from typing import Optional
from asyncio import StreamReader, StreamWriter

from .models import Message, UserSession
from .stores import MessageStore, UserSessionStore
from .managers import ConnectionManager
from .srp_auth import SRPAuthManager
from ..constants import (
    AUTH_TIMEOUT_SEC,
    CLEANUP_INTERVAL_SEC,
    DEFAULT_PORT,
    ROOM_SALT_BYTES,
)

_b64e = lambda data: base64.b64encode(data).decode()
_b64d = base64.b64decode


class ChatServer:
    """Async TCP chat server with SRP auth and E2EE message relay."""

    __slots__ = (
        "_messages",
        "_sessions",
        "_connections",
        "_srp",
        "_room_salt",
        "_admin_user_id",
        "_cleanup_task",
    )

    def __init__(self, password: str):
        self._messages = MessageStore()
        self._sessions = UserSessionStore()
        self._connections = ConnectionManager()
        self._srp = SRPAuthManager(password)
        self._room_salt = os.urandom(ROOM_SALT_BYTES)
        self._admin_user_id: Optional[str] = None  # first user to join
        self._cleanup_task: Optional[asyncio.Task] = None

    # ── Lifecycle ──────────────────────────────────────────

    async def start(self, host: str, port: int):
        server = await asyncio.start_server(self._handle_client, host, port)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        addr = server.sockets[0].getsockname()
        print(f"[*] Server running on {addr[0]}:{addr[1]}")
        async with server:
            await server.serve_forever()

    async def stop(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            await asyncio.gather(self._cleanup_task, return_exceptions=True)

    async def _cleanup_loop(self):
        """Periodically remove stale sessions."""
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL_SEC)
            removed = self._sessions.cleanup_stale()
            if removed:
                print(f"[*] Cleaned {removed} stale session(s)")

    # ── Client handler ─────────────────────────────────────

    async def _handle_client(self, reader: StreamReader, writer: StreamWriter):
        user_id = None
        try:
            session = await self._authenticate(reader, writer)
            if not session:
                return
            user_id = session.user_id

            # First authenticated user becomes admin (can clear chat)
            if self._admin_user_id is None:
                self._admin_user_id = user_id

            await self._chat_loop(reader, writer, session)

        except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            print(f"[!] Client error: {e}")
        finally:
            if user_id:
                await self._connections.disconnect(user_id)
                self._sessions.remove(user_id)
                await self._connections.broadcast(
                    json.dumps({"type": "user_left", "user_id": user_id})
                )
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    # ── SRP Authentication ─────────────────────────────────

    async def _authenticate(
        self, reader: StreamReader, writer: StreamWriter
    ) -> Optional[UserSession]:
        """Two-step SRP handshake: init → verify.

        Returns a UserSession on success, None on failure.
        The session_key derived by SRP is intentionally NOT sent
        back to the client — room_key derivation happens client-side
        via HKDF(password, room_salt).
        """
        readline = lambda: asyncio.wait_for(reader.readline(), AUTH_TIMEOUT_SEC)

        # ── Step 1: srp_init ───────────────────────────────
        line = await readline()
        if not line:
            return None

        data = self._parse_json(line)
        if not data:
            return await self._send_error(writer, "Invalid JSON")

        if data.get("cmd") != "srp_init":
            return await self._send_error(writer, "Expected srp_init")

        username = data.get("username", "unknown")
        client_A = data.get("A")

        if not client_A:
            return await self._send_error(writer, "Missing public ephemeral A")

        if self._sessions.username_exists(username):
            return await self._send_error(writer, "Username taken")

        try:
            client_public = _b64d(client_A)
            user_id, B, salt = self._srp.init_auth(username, client_public)
        except Exception:
            return await self._send_error(writer, "SRP init failed")

        await self._send_json(writer, {
            "user_id": user_id,
            "B": _b64e(B),
            "salt": _b64e(salt),
            "room_salt": _b64e(self._room_salt),
        })

        # ── Step 2: srp_verify ─────────────────────────────
        line = await readline()
        if not line:
            return None

        data = self._parse_json(line)
        if not data:
            return await self._send_error(writer, "Invalid JSON")

        if data.get("cmd") != "srp_verify":
            return await self._send_error(writer, "Expected srp_verify")

        if data.get("user_id") != user_id or not data.get("M"):
            return await self._send_error(writer, "Invalid verify payload")

        try:
            client_proof = _b64d(data["M"])
            H_AMK, _session_key = self._srp.verify_auth(user_id, client_proof)
        except ValueError as e:
            return await self._send_error(writer, str(e))

        # Send server proof so client can verify us too.
        # NOTE: session_key is NOT included — this was a security
        # bug in v1 that leaked key material over the wire.
        await self._send_json(writer, {"H_AMK": _b64e(H_AMK)})

        session = UserSession(user_id=user_id, username=username)
        self._sessions.add(session)
        return session

    # ── Chat loop ──────────────────────────────────────────

    async def _chat_loop(
        self, reader: StreamReader, writer: StreamWriter, session: UserSession
    ):
        user_id = session.user_id

        await self._connections.connect(user_id, writer)

        # Send current state to the newly joined client
        await self._send_json(writer, {
            "type": "init",
            "messages": [asdict(m) for m in self._messages.get_all()],
            "users": [
                {"user_id": u.user_id, "username": u.username}
                for u in self._sessions.get_all()
            ],
        })

        # Notify others
        await self._connections.broadcast(
            json.dumps({
                "type": "user_joined",
                "user_id": user_id,
                "username": session.username,
            }),
            exclude_user=user_id,
        )

        # Main message loop
        while True:
            line = await reader.readline()
            if not line:
                break

            self._sessions.update_activity(user_id)

            data = self._parse_json(line)
            if not data:
                continue

            match data.get("type"):
                case "message":
                    text = data.get("text", "")
                    if not text:
                        continue
                    message = Message(text=text, username=session.username)
                    self._messages.add(message)  # assigns index
                    await self._connections.broadcast(
                        json.dumps({"type": "message", "data": asdict(message)})
                    )

                case "clear":
                    # Only admin (first user) can clear history
                    if user_id != self._admin_user_id:
                        await self._send_json(writer, {
                            "error": "Only admin can clear chat"
                        })
                        continue
                    self._messages.clear()
                    await self._connections.broadcast(
                        json.dumps({"type": "cleared"})
                    )

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _parse_json(line: bytes) -> Optional[dict]:
        try:
            return json.loads(line.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    @staticmethod
    async def _send_json(writer: StreamWriter, data: dict):
        writer.write((json.dumps(data) + "\n").encode())
        await writer.drain()

    async def _send_error(self, writer: StreamWriter, error: str) -> None:
        await self._send_json(writer, {"error": error})
        return None


def run_server(
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    password: Optional[str] = None,
):
    if not password:
        raise ValueError("Server password is required")
    server = ChatServer(password)
    try:
        asyncio.run(server.start(host, port))
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
