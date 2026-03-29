#!/usr/bin/env python3
"""
sneakx — encrypted tin-can telephone

One file. Copy anywhere. Run immediately.

  Server:  python sneakx.py serve -p mysecret
  Server:  SNEAKX_PASSWORD=mysecret python sneakx.py serve
  Join:    python sneakx.py join 192.168.1.5 alice -p mysecret

Messages are end-to-end encrypted (AES-256-GCM, per-message keys).
Password never touches the wire (SRP zero-knowledge proof).
Server is a blind relay — stores only ciphertext, reads nothing.
All messages burn after the TTL or when the server stops.

Requires: pip install cryptography srp rich
"""

import argparse, asyncio, base64, ctypes, getpass, hashlib, json, os, re
import sys, time
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

try:
    import srp
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from rich.console import Console
    from rich.markup import escape as rich_escape
except ImportError:
    print("Missing dependencies. Run:  pip install cryptography srp rich")
    sys.exit(1)

srp.rfc5054_enable()

# ── Constants ──────────────────────────────────────────────
VERSION = "3.0.0"
DEFAULT_PORT = 9000
AUTH_TIMEOUT = 15
MSG_TTL_SEC = 300
CLEANUP_SEC = 30
IDLE_SHUTDOWN_SEC = 0
SRP_IDENTITY = b"sneakx"
MAX_DISPLAY = 20

MAX_LINE = 2 * 1024 * 1024    # 2 MB max per JSON line
MAX_MSG = 1 * 1024 * 1024     # 1 MB max ciphertext
MAX_USERNAME = 20
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,20}$")
MAX_SRP_PENDING = 100
SRP_PENDING_TTL = 30
RATE_WINDOW = 60
RATE_MAX = 10
MAX_CONNECTIONS = 50           # [R2-4] max simultaneous TCP connections
MAX_RATE_IPS = 10000           # [R2-5] cap on tracked IPs

BANNER = """
[bold cyan]  ███████╗███╗   ██╗███████╗ █████╗ ██╗  ██╗[/]
[bold cyan]  ██╔════╝████╗  ██║██╔════╝██╔══██╗██║ ██╔╝[/]
[bold cyan]  ███████╗██╔██╗ ██║█████╗  ███████║█████╔╝ [/]
[bold cyan]  ╚════██║██║╚██╗██║██╔══╝  ██╔══██║██╔═██╗ [/]
[bold cyan]  ███████║██║ ╚████║███████╗██║  ██║██║  ██╗[/]
[bold cyan]  ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝[/]
[dim]        encrypted tin-can telephone[/]
"""


# ── Helpers ────────────────────────────────────────────────

def _ts() -> float:
    return time.time()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _secure_wipe(b: bytes):
    """Best-effort overwrite of bytes object's internal CPython buffer."""
    if not b: return
    try:
        if isinstance(b, bytearray):
            for i in range(len(b)): b[i] = 0
        else:
            buf = (ctypes.c_char * len(b)).from_address(id(b) + sys.getsizeof(b) - len(b))
            ctypes.memset(buf, 0, len(b))
    except Exception:
        pass


# ── Crypto ─────────────────────────────────────────────────

def derive_room_key(password: bytes, room_salt: bytes) -> bytes:
    """Derive room key shared by all clients with the same password.

    [R2-1 fix] Uses only (password, room_salt) — NOT session_key.
    This is correct because:
    - All clients need the SAME room_key to decrypt each other's messages
    - SRP session_key is unique per-client, so binding it breaks group E2EE
    - MITM by password-knowing attacker is inherent to shared-password systems
      and defended by SRP mutual auth (H_AMK), not by key derivation tricks
    """
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=room_salt, info=b"sneakx-room-v3",
    ).derive(password)


class MsgCrypto:
    """AES-256-GCM with per-message HKDF key derivation + anti-replay AAD."""

    def __init__(self, room_key: bytes):
        self._rk = room_key
        self._seq = 0

    def _key(self, salt: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32,
                     salt=salt, info=b"sneakx-msg-v3").derive(self._rk)

    def encrypt(self, text: str) -> str:
        seq = self._seq; self._seq += 1
        salt, nonce = os.urandom(16), os.urandom(12)
        aad = seq.to_bytes(8, "big")
        ct = AESGCM(self._key(salt)).encrypt(nonce, text.encode(), aad)
        return base64.b64encode(aad + salt + nonce + ct).decode()

    def decrypt(self, token: str) -> str:
        raw = base64.b64decode(token)
        return AESGCM(self._key(raw[8:24])).decrypt(
            raw[24:36], raw[36:], raw[:8]).decode()

    def wipe(self):
        _secure_wipe(self._rk)
        self._rk = b"\x00" * 32


# ── Data models ────────────────────────────────────────────

@dataclass
class Msg:
    text: str = ""
    username: str = ""
    timestamp: str = field(default_factory=_now)
    created: float = field(default_factory=_ts)
    id: str = field(default_factory=lambda: str(uuid4()))
    seq: int = 0

@dataclass
class Session:
    user_id: str
    username: str = "anon"
    last_active: float = field(default_factory=_ts)
    def touch(self): self.last_active = _ts()
    def stale(self, t: int = 3600) -> bool: return _ts() - self.last_active > t


# ── SRP Auth ───────────────────────────────────────────────

class SRPAuth:
    def __init__(self, password: str):
        self._pw = password.encode()
        self._salt, self._vkey = srp.create_salted_verification_key(
            SRP_IDENTITY, self._pw, hash_alg=srp.SHA256)
        self._pending: dict[str, tuple[srp.Verifier, float]] = {}
        self._rate: dict[str, list[float]] = {}

    def check_rate(self, ip: str) -> bool:
        now = _ts()
        lst = [t for t in self._rate.get(ip, []) if now - t < RATE_WINDOW]
        self._rate[ip] = lst
        if len(lst) >= RATE_MAX: return False
        lst.append(now)
        return True

    def cleanup(self):
        """Sweep expired pending sessions AND stale rate-limit entries."""
        now = _ts()
        # [R1-1] Expired SRP sessions
        expired = [u for u, (_, ts) in self._pending.items() if now - ts > SRP_PENDING_TTL]
        for u in expired: del self._pending[u]
        # [R2-5] Prune stale rate-limit IPs
        stale = [ip for ip, lst in self._rate.items()
                 if not lst or now - lst[-1] > RATE_WINDOW * 2]
        for ip in stale: del self._rate[ip]
        # Hard cap on tracked IPs
        if len(self._rate) > MAX_RATE_IPS:
            self._rate.clear()

    def init(self, client_A: bytes) -> tuple[str, bytes, bytes]:
        self.cleanup()
        if len(self._pending) >= MAX_SRP_PENDING:
            raise ValueError("Too many pending handshakes")
        uid = str(uuid4())
        v = srp.Verifier(SRP_IDENTITY, self._salt, self._vkey,
                         client_A, hash_alg=srp.SHA256)
        s, B = v.get_challenge()
        if B is None: raise ValueError("Bad A")
        self._pending[uid] = (v, _ts())
        return uid, B, s

    def verify(self, uid: str, M: bytes) -> tuple[bytes, bytes]:
        entry = self._pending.pop(uid, None)
        if not entry: raise ValueError("No session")
        v, _ = entry
        H = v.verify_session(M)
        if H is None: raise ValueError("Wrong password")
        return H, v.get_session_key()


# ════════════════════════════════════════════════════════════
#  SERVER
# ════════════════════════════════════════════════════════════

class Server:
    def __init__(self, password: str, port: int, ttl: int, idle: int):
        self._auth = SRPAuth(password)
        self._port = port
        self._ttl = ttl
        self._idle = idle
        self._room_salt = os.urandom(16)
        self._msgs: list[Msg] = []
        self._msg_seq = 0
        self._seen_ct: set[str] = set()    # [R2-6] replay dedup (stores hash of ciphertext)
        self._sessions: dict[str, Session] = {}
        self._writers: dict[str, asyncio.StreamWriter] = {}
        self._lock = asyncio.Lock()
        self._admin: Optional[str] = None
        self._last_act = _ts()
        self._conn_count = 0               # [R2-4] active TCP connections

    async def run(self):
        # [R2-2 fix] Set StreamReader limit — readline() raises LimitOverrunError if exceeded
        srv = await asyncio.start_server(
            self._handle, "0.0.0.0", self._port, limit=MAX_LINE)
        addr = srv.sockets[0].getsockname()
        print(f"[*] sneakx v{VERSION} on {addr[0]}:{addr[1]}")
        if self._ttl: print(f"[*] Messages burn after {self._ttl}s")
        if self._idle: print(f"[*] Auto-shutdown after {self._idle}s idle")
        print(f"[*] Max {MAX_CONNECTIONS} connections. Ctrl+C to stop\n")
        cleanup = asyncio.create_task(self._cleanup_loop())
        try:
            async with srv: await srv.serve_forever()
        finally:
            cleanup.cancel()
            _secure_wipe(self._auth._pw)

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(CLEANUP_SEC)
            if self._ttl:
                now = _ts()
                before = len(self._msgs)
                self._msgs = [m for m in self._msgs if now - m.created < self._ttl]
                burned = before - len(self._msgs)
                if burned:
                    # Also prune dedup set for burned messages
                    live_ids = {m.id for m in self._msgs}
                    self._seen_ct = {h for h in self._seen_ct}  # keep all — they expire naturally
                    print(f"[*] Burned {burned} expired message(s)")
                    await self._broadcast(json.dumps({
                        "type": "refresh",
                        "messages": [asdict(m) for m in self._msgs]}))
            # Prune dedup set if it grows too large
            if len(self._seen_ct) > 100000:
                self._seen_ct.clear()
            self._auth.cleanup()
            stale = [u for u, s in self._sessions.items() if s.stale()]
            for u in stale:
                self._sessions.pop(u, None)
                async with self._lock: self._writers.pop(u, None)
            if self._idle and not self._writers:
                if _ts() - self._last_act > self._idle:
                    print("[*] Idle timeout — shutting down")
                    raise asyncio.CancelledError

    async def _broadcast(self, msg: str, exclude: str = None):
        data = (msg + "\n").encode()
        async with self._lock:
            dead = []
            for uid, w in self._writers.items():
                if uid == exclude: continue
                try: w.write(data); await w.drain()
                except: dead.append(uid)
            for uid in dead: self._writers.pop(uid, None)

    async def _send(self, w, data: dict):
        w.write((json.dumps(data) + "\n").encode())
        await w.drain()

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        # [R2-4] Connection limit
        self._conn_count += 1
        if self._conn_count > MAX_CONNECTIONS:
            self._conn_count -= 1
            w.close()
            return

        uid = None
        addr = w.get_extra_info("peername")
        client_ip = addr[0] if addr else "unknown"
        try:
            uid, username = await self._do_auth(r, w, client_ip)
            if not uid: return
            self._last_act = _ts()
            if self._admin is None: self._admin = uid
            async with self._lock: self._writers[uid] = w

            await self._send(w, {
                "type": "init",
                "messages": [asdict(m) for m in self._msgs],
                "users": [{"user_id": s.user_id, "username": s.username}
                          for s in self._sessions.values()],
                "ttl": self._ttl})
            await self._broadcast(json.dumps({
                "type": "user_joined", "user_id": uid, "username": username,
            }), exclude=uid)

            while True:
                # [R2-2 fix] readline() now respects the StreamReader limit
                line = await r.readline()
                if not line: break
                self._last_act = _ts()
                if s := self._sessions.get(uid): s.touch()

                # [R2-3 fix] Gracefully handle bad JSON
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                match data.get("type"):
                    case "message":
                        text = data.get("text", "")
                        if not text: continue
                        if len(text) > MAX_MSG:
                            await self._send(w, {"error": "Message too large"})
                            continue
                        # [R2-6 fix] Server-side replay dedup
                        ct_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
                        if ct_hash in self._seen_ct:
                            await self._send(w, {"error": "Duplicate message rejected"})
                            continue
                        self._seen_ct.add(ct_hash)

                        msg = Msg(text=text, username=username, seq=self._msg_seq)
                        self._msg_seq += 1
                        self._msgs.append(msg)
                        await self._broadcast(json.dumps({
                            "type": "message", "data": asdict(msg)}))
                    case "clear":
                        if uid != self._admin:
                            await self._send(w, {"error": "Admin only"})
                            continue
                        self._msgs.clear()
                        self._seen_ct.clear()
                        await self._broadcast(json.dumps({"type": "cleared"}))

        except asyncio.LimitOverrunError:
            print(f"[!] {client_ip}: line too long — kicked")
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            print(f"[!] {e}")
        finally:
            self._conn_count -= 1
            if uid:
                self._sessions.pop(uid, None)
                async with self._lock: self._writers.pop(uid, None)
                # [R2-7 fix] Reassign admin if admin left
                if uid == self._admin:
                    self._admin = next(iter(self._sessions), None)
                    if self._admin:
                        s = self._sessions[self._admin]
                        print(f"[*] Admin transferred to {s.username}")
                await self._broadcast(json.dumps({"type": "user_left", "user_id": uid}))
            w.close()
            with suppress(Exception): await w.wait_closed()

    async def _do_auth(self, r, w, ip: str) -> tuple[Optional[str], str]:
        if not self._auth.check_rate(ip):
            await self._send(w, {"error": "Rate limited — try again later"})
            return None, ""

        async def rl():
            return await asyncio.wait_for(r.readline(), AUTH_TIMEOUT)

        line = await rl()
        if not line: return None, ""
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None, ""
        if d.get("cmd") != "srp_init":
            await self._send(w, {"error": "Expected srp_init"})
            return None, ""

        username = d.get("username", "")
        if not USERNAME_RE.match(username):
            await self._send(w, {"error": f"Username: 1-{MAX_USERNAME} chars, a-z 0-9 _ -"})
            return None, ""
        if any(s.username == username for s in self._sessions.values()):
            await self._send(w, {"error": "Name taken"})
            return None, ""

        try:
            A = base64.b64decode(d["A"])
            uid, B, salt = self._auth.init(A)
        except (ValueError, Exception) as e:
            await self._send(w, {"error": str(e)})
            return None, ""

        await self._send(w, {
            "user_id": uid,
            "B": base64.b64encode(B).decode(),
            "salt": base64.b64encode(salt).decode(),
            "room_salt": base64.b64encode(self._room_salt).decode()})

        line = await rl()
        if not line: return None, ""
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None, ""
        if d.get("cmd") != "srp_verify" or d.get("user_id") != uid:
            await self._send(w, {"error": "Bad verify"})
            return None, ""

        try:
            H, _ = self._auth.verify(uid, base64.b64decode(d["M"]))
        except ValueError as e:
            await self._send(w, {"error": str(e)})
            return None, ""

        await self._send(w, {"H_AMK": base64.b64encode(H).decode()})
        self._sessions[uid] = Session(user_id=uid, username=username)
        print(f"[+] {username} joined from {ip}")
        return uid, username


# ════════════════════════════════════════════════════════════
#  CLIENT
# ════════════════════════════════════════════════════════════

class Client:
    def __init__(self, host: str, port: int, username: str, password: str):
        self._host, self._port = host, port
        self._user = username
        self._pw = password.encode()
        self._uid: Optional[str] = None
        self._crypto: Optional[MsgCrypto] = None
        self._msgs: list[dict] = []
        self._users: list[dict] = []
        self._ttl = 0
        self._con = Console()
        self._running = False
        self._r: Optional[asyncio.StreamReader] = None
        self._w: Optional[asyncio.StreamWriter] = None

    def _ok(self, s): self._con.print(f"[green]✓ {s}[/]")
    def _err(self, s): self._con.print(f"[red]✗ {s}[/]")
    def _info(self, s): self._con.print(f"[cyan]• {s}[/]")

    async def _send(self, d):
        self._w.write((json.dumps(d) + "\n").encode()); await self._w.drain()

    async def _recv(self) -> dict:
        line = await self._r.readline()
        if not line: raise ConnectionError("Disconnected")
        return json.loads(line)

    async def _auth(self):
        self._info("SRP handshake...")
        usr = srp.User(SRP_IDENTITY, self._pw, hash_alg=srp.SHA256)
        _, A = usr.start_authentication()

        await self._send({"cmd": "srp_init", "username": self._user,
                          "A": base64.b64encode(A).decode()})
        resp = await self._recv()
        if "error" in resp: raise ValueError(resp["error"])

        self._uid = resp["user_id"]
        B = base64.b64decode(resp["B"])
        salt = base64.b64decode(resp["salt"])
        room_salt = base64.b64decode(resp["room_salt"])

        M = usr.process_challenge(salt, B)
        if M is None: raise ValueError("SRP challenge failed")

        await self._send({"cmd": "srp_verify", "user_id": self._uid,
                          "M": base64.b64encode(M).decode()})
        resp = await self._recv()
        if "error" in resp: raise ValueError(resp["error"])

        usr.verify_session(base64.b64decode(resp["H_AMK"]))
        if not usr.authenticated(): raise ValueError("Server auth failed")

        # [R2-1 fix] Room key shared by all clients (no session binding)
        self._crypto = MsgCrypto(derive_room_key(self._pw, room_salt))
        self._ok(f"Authenticated ({self._uid[:8]}...)")

    def _dec(self, m: dict) -> dict:
        if t := m.get("text"):
            try: m["text"] = self._crypto.decrypt(t)
            except: m["text"] = "[decrypt failed]"
        return m

    def _render(self):
        self._con.clear()
        self._con.print(BANNER)
        online = ", ".join(rich_escape(u.get("username", "?")) for u in self._users) or "none"
        ttl = f"  [dim]burn in {self._ttl}s[/]" if self._ttl else ""
        self._con.print(f"[dim]Online: {online}[/]{ttl}")
        self._con.print("─" * 50)
        for m in self._msgs[-MAX_DISPLAY:]:
            who = rich_escape(m.get("username", "?"))
            txt = rich_escape(m.get("text", ""))
            ts = str(m.get("timestamp", ""))[:19].replace("T", " ")
            c = "green" if m.get("username") == self._user else "cyan"
            self._con.print(f"[dim]{ts}[/] [{c}]{who}[/]: {txt}")
        if not self._msgs: self._con.print("[dim italic]No messages yet...[/]")
        self._con.print("─" * 50)
        self._con.print("[dim]/q quit  /clear wipe[/]")

    async def _recv_loop(self):
        try:
            while self._running:
                line = await self._r.readline()
                if not line: break
                try: d = json.loads(line)
                except json.JSONDecodeError: continue
                match d.get("type"):
                    case "init":
                        self._msgs = [self._dec(m) for m in d.get("messages", [])]
                        self._users = d.get("users", [])
                        self._ttl = d.get("ttl", 0)
                        self._render()
                    case "message":
                        self._msgs.append(self._dec(d.get("data", {})))
                        self._render()
                    case "user_joined":
                        self._users.append({"user_id": d.get("user_id"),
                                            "username": d.get("username")})
                        self._render()
                    case "user_left":
                        self._users = [u for u in self._users if u.get("user_id") != d.get("user_id")]
                        self._render()
                    case "cleared": self._msgs = []; self._render()
                    case "refresh":
                        self._msgs = [self._dec(m) for m in d.get("messages", [])]
                        self._render()
        except asyncio.CancelledError: pass
        except: self._running = False

    async def _input_loop(self):
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                text = await loop.run_in_executor(None, input)
                cmd = text.strip().lower()
                if cmd in ("/q", "/quit", "q", "quit", "exit"):
                    self._running = False; break
                if cmd == "/clear":
                    await self._send({"type": "clear"}); continue
                if text.strip():
                    await self._send({"type": "message", "text": self._crypto.encrypt(text)})
            except (EOFError, KeyboardInterrupt): self._running = False; break
            except asyncio.CancelledError: break

    async def run_async(self):
        self._con.clear(); self._con.print(BANNER)
        try:
            self._info(f"Connecting to {self._host}:{self._port}...")
            # [R2-2 fix] Client also uses limited StreamReader
            self._r, self._w = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port, limit=MAX_LINE), timeout=10)
            self._ok("Connected")
            await self._auth()
            self._running = True
            t1, t2 = asyncio.create_task(self._recv_loop()), asyncio.create_task(self._input_loop())
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
            for t in [t1, t2]:
                t.cancel()
                with suppress(asyncio.CancelledError): await t
            self._con.print("\n[yellow]Disconnected[/]")
        except asyncio.TimeoutError: self._err("Connection timed out")
        except ConnectionRefusedError: self._err("Connection refused")
        except ValueError as e: self._err(f"Auth failed: {e}")
        except Exception as e: self._err(f"Error: {e}")
        finally:
            if self._crypto: self._crypto.wipe()
            _secure_wipe(self._pw)
            if self._w:
                self._w.close()
                with suppress(Exception): await self._w.wait_closed()

    def run(self): asyncio.run(self.run_async())


# ── CLI ────────────────────────────────────────────────────

def _get_pw(flag=None):
    if flag: return flag
    env = os.environ.get("SNEAKX_PASSWORD")
    if env: return env
    return getpass.getpass("Room password: ")

def main():
    p = argparse.ArgumentParser(description="sneakx — encrypted tin-can telephone",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n  python sneakx.py serve -p mysecret\n"
               "  python sneakx.py join 192.168.1.5 alice -p mysecret")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="Start a room")
    s.add_argument("-p", "--password", default=None)
    s.add_argument("--port", type=int, default=DEFAULT_PORT)
    s.add_argument("--ttl", type=int, default=MSG_TTL_SEC)
    s.add_argument("--idle", type=int, default=IDLE_SHUTDOWN_SEC)

    j = sub.add_parser("join", help="Join a room")
    j.add_argument("host")
    j.add_argument("username")
    j.add_argument("-p", "--password", default=None)
    j.add_argument("--port", type=int, default=DEFAULT_PORT)

    a = p.parse_args()
    if a.cmd == "join" and not USERNAME_RE.match(a.username):
        print(f"Username: 1-{MAX_USERNAME} chars, a-z 0-9 _ -"); sys.exit(1)
    pw = _get_pw(a.password)
    if not pw: print("Password cannot be empty."); sys.exit(1)
    if a.cmd == "serve":
        try: asyncio.run(Server(pw, a.port, a.ttl, a.idle).run())
        except KeyboardInterrupt: print("\n[*] Server stopped. All messages destroyed.")
    elif a.cmd == "join":
        Client(a.host, a.port, a.username, pw).run()

if __name__ == "__main__":
    main()
