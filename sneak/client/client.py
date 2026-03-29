"""
sneak client.

Connects to a sneak server over TCP, authenticates via SRP,
then enters an encrypted chat session. All messages are encrypted
client-side with AES-256-GCM before transmission; the server
never sees plaintext.
"""

import asyncio
import json
import base64
from typing import Optional

import srp
from rich.console import Console

from ..constants import (
    CONNECTION_TIMEOUT_SEC,
    MAX_DISPLAY_MESSAGES,
    SRP_IDENTITY,
)
from ..crypto import derive_room_key, MessageCrypto

srp.rfc5054_enable()

BANNER = """
[bold cyan]  ███████╗███╗   ██╗███████╗ █████╗ ██╗  ██╗[/]
[bold cyan]  ██╔════╝████╗  ██║██╔════╝██╔══██╗██║ ██╔╝[/]
[bold cyan]  ███████╗██╔██╗ ██║█████╗  ███████║█████╔╝ [/]
[bold cyan]  ╚════██║██║╚██╗██║██╔══╝  ██╔══██║██╔═██╗ [/]
[bold cyan]  ███████║██║ ╚████║███████╗██║  ██║██║  ██╗[/]
[bold cyan]  ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝[/]
[dim]          e2e encrypted terminal chat[/]
"""


class Client:
    """Terminal chat client with SRP auth and E2EE."""

    def __init__(
        self,
        server: str,
        port: int,
        username: str,
        password: Optional[str] = None,
    ):
        self.server = server
        self.port = port
        self.username = username
        self._password = (password or "").encode()

        # Set after authentication
        self.user_id: Optional[str] = None
        self._crypto: Optional[MessageCrypto] = None

        # UI state
        self.console = Console()
        self.messages: list[dict] = []
        self.users: list[dict] = []
        self.connected = False
        self.running = False

        # Network
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    # ── Console helpers ────────────────────────────────────

    def _success(self, msg: str) -> None:
        self.console.print(f"[green]✓ {msg}[/]")

    def _error(self, msg: str) -> None:
        self.console.print(f"[red]✗ {msg}[/]")

    def _info(self, msg: str) -> None:
        self.console.print(f"[cyan]• {msg}[/]")

    # ── Network helpers ────────────────────────────────────

    async def _send_json(self, data: dict) -> None:
        self.writer.write((json.dumps(data) + "\n").encode())
        await self.writer.drain()

    async def _recv_json(self) -> dict:
        line = await self.reader.readline()
        if not line:
            raise ConnectionError("Connection closed by server")
        return json.loads(line.decode())

    # ── SRP Authentication ─────────────────────────────────

    async def _authenticate(self) -> None:
        """Perform SRP handshake, then derive room_key locally.

        After this method:
          - self.user_id is set
          - self._crypto is ready for encrypt/decrypt
          - No key material was sent over the wire
        """
        self._info("Starting SRP handshake...")

        usr = srp.User(SRP_IDENTITY, self._password, hash_alg=srp.SHA256)
        _, A = usr.start_authentication()

        # Step 1: send client public ephemeral
        await self._send_json({
            "cmd": "srp_init",
            "username": self.username,
            "A": base64.b64encode(A).decode(),
        })

        resp = await self._recv_json()
        if "error" in resp:
            raise ValueError(resp["error"])

        self.user_id = resp["user_id"]
        B = base64.b64decode(resp["B"])
        salt = base64.b64decode(resp["salt"])
        room_salt = base64.b64decode(resp["room_salt"])

        # Derive room encryption key locally (never transmitted)
        room_key = derive_room_key(self._password, room_salt)
        self._crypto = MessageCrypto(room_key)

        # Step 2: send client proof
        M = usr.process_challenge(salt, B)
        if M is None:
            raise ValueError("SRP challenge processing failed")

        await self._send_json({
            "cmd": "srp_verify",
            "user_id": self.user_id,
            "M": base64.b64encode(M).decode(),
        })

        resp = await self._recv_json()
        if "error" in resp:
            raise ValueError(resp["error"])

        # Verify server's proof (mutual authentication)
        H_AMK = base64.b64decode(resp["H_AMK"])
        usr.verify_session(H_AMK)

        if not usr.authenticated():
            raise ValueError("Server authentication failed")

        self._success(f"Authenticated (session: {self.user_id[:8]}...)")

    # ── Message handling ───────────────────────────────────

    def _decrypt_message(self, msg: dict) -> dict:
        """Attempt to decrypt a message's text field in-place."""
        if text := msg.get("text"):
            try:
                msg["text"] = self._crypto.decrypt(text)
            except Exception:
                msg["text"] = "[decrypt failed]"
        return msg

    def _render(self) -> None:
        """Redraw the full chat UI."""
        self.console.clear()
        self.console.print(BANNER)
        self.console.print()

        online = ", ".join(u.get("username", "?") for u in self.users) or "none"
        self.console.print(f"[dim]Online: {online}[/]")
        self.console.print("─" * 60)

        visible = self.messages[-MAX_DISPLAY_MESSAGES:]
        for msg in visible:
            username = msg.get("username", "unknown")
            text = msg.get("text", "")
            ts = str(msg.get("timestamp", ""))[:19].replace("T", " ")
            style = "green" if username == self.username else "cyan"
            self.console.print(f"[dim]{ts}[/] [{style}]{username}[/]: {text}")

        if not visible:
            self.console.print("[dim italic]No messages yet...[/]")

        self.console.print("─" * 60)
        self.console.print("[dim]Type a message and press Enter. /clear to clear, /q to quit.[/]")

    # ── Event loops ────────────────────────────────────────

    async def _receive_loop(self) -> None:
        """Listen for server broadcasts and update local state."""
        try:
            while self.running:
                line = await self.reader.readline()
                if not line:
                    break

                data = json.loads(line.decode())
                msg_type = data.get("type", "")

                match msg_type:
                    case "init":
                        self.messages = [
                            self._decrypt_message(m)
                            for m in data.get("messages", [])
                        ]
                        self.users = data.get("users", [])
                        self.connected = True
                        self._render()

                    case "message":
                        msg = self._decrypt_message(data.get("data", {}))
                        self.messages.append(msg)
                        self._render()

                    case "user_joined":
                        self.users.append({
                            "user_id": data.get("user_id"),
                            "username": data.get("username"),
                        })
                        self._render()

                    case "user_left":
                        left_id = data.get("user_id")
                        self.users = [
                            u for u in self.users
                            if u.get("user_id") != left_id
                        ]
                        self._render()

                    case "cleared":
                        self.messages = []
                        self._render()

        except asyncio.CancelledError:
            pass
        except Exception:
            self.connected = False

    async def _input_loop(self) -> None:
        """Read user input from stdin and send encrypted messages."""
        loop = asyncio.get_event_loop()
        while self.running:
            try:
                text = await loop.run_in_executor(None, input)

                if text.lower() in ("/q", "/quit", "q", "quit", "exit"):
                    self.running = False
                    break

                if text.strip().lower() == "/clear":
                    await self._send_json({"type": "clear"})
                    continue

                if text.strip():
                    encrypted = self._crypto.encrypt(text)
                    await self._send_json({"type": "message", "text": encrypted})

            except (EOFError, KeyboardInterrupt):
                self.running = False
                break
            except asyncio.CancelledError:
                break

    # ── Main entry point ───────────────────────────────────

    async def _run_async(self) -> None:
        self.console.clear()
        self.console.print(BANNER)
        self.console.print()

        try:
            self._info(f"Connecting to {self.server}:{self.port}...")
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.server, self.port),
                timeout=CONNECTION_TIMEOUT_SEC,
            )
            self._success("Connected")

            await self._authenticate()
            self.running = True

            recv_task = asyncio.create_task(self._receive_loop())
            input_task = asyncio.create_task(self._input_loop())

            done, pending = await asyncio.wait(
                [recv_task, input_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            self.console.print("\n[yellow]Disconnected[/]")

        except asyncio.TimeoutError:
            self._error(f"Connection timed out ({self.server}:{self.port})")
        except ConnectionRefusedError:
            self._error(f"Connection refused ({self.server}:{self.port})")
        except ConnectionError as e:
            self._error(f"Connection error: {e}")
        except ValueError as e:
            self._error(f"Authentication failed: {e}")
        except Exception:
            import traceback
            self._error("Unexpected error")
            traceback.print_exc()
        finally:
            # Wipe key material
            if self._crypto:
                self._crypto.wipe()
            if self.writer:
                self.writer.close()
                with asyncio.suppress(Exception):
                    await self.writer.wait_closed()

    def run(self) -> None:
        """Blocking entry point — runs the async event loop."""
        asyncio.run(self._run_async())
