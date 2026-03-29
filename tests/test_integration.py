"""Integration test: full SRP auth + E2EE message roundtrip over TCP."""

import asyncio
import json
import base64
import pytest

import srp

from sneak.server.server import ChatServer
from sneak.crypto import derive_room_key, MessageCrypto
from sneak.constants import SRP_IDENTITY

srp.rfc5054_enable()

PASSWORD = "integration-test-password"


async def _send(writer, data: dict):
    writer.write((json.dumps(data) + "\n").encode())
    await writer.drain()


async def _recv(reader) -> dict:
    line = await asyncio.wait_for(reader.readline(), timeout=5)
    return json.loads(line.decode())


async def _authenticate(reader, writer, username: str, password: str):
    """Perform full SRP handshake, return (user_id, MessageCrypto)."""
    usr = srp.User(SRP_IDENTITY, password.encode(), hash_alg=srp.SHA256)
    _, A = usr.start_authentication()

    await _send(writer, {
        "cmd": "srp_init",
        "username": username,
        "A": base64.b64encode(A).decode(),
    })

    resp = await _recv(reader)
    assert "error" not in resp, resp.get("error")

    user_id = resp["user_id"]
    B = base64.b64decode(resp["B"])
    salt = base64.b64decode(resp["salt"])
    room_salt = base64.b64decode(resp["room_salt"])

    room_key = derive_room_key(password.encode(), room_salt)
    crypto = MessageCrypto(room_key)

    M = usr.process_challenge(salt, B)
    assert M is not None

    await _send(writer, {
        "cmd": "srp_verify",
        "user_id": user_id,
        "M": base64.b64encode(M).decode(),
    })

    resp = await _recv(reader)
    assert "error" not in resp

    H_AMK = base64.b64decode(resp["H_AMK"])
    usr.verify_session(H_AMK)
    assert usr.authenticated()

    # v2: server no longer leaks session_key
    assert "session_key" not in resp

    return user_id, crypto


@pytest.mark.asyncio
async def test_full_roundtrip():
    """Start server, connect two clients, exchange encrypted messages."""
    server = ChatServer(PASSWORD)
    tcp_server = await asyncio.start_server(
        server._handle_client, "127.0.0.1", 0
    )
    port = tcp_server.sockets[0].getsockname()[1]

    try:
        # ── Client A connects ──────────────────────────────
        r1, w1 = await asyncio.open_connection("127.0.0.1", port)
        uid1, crypto1 = await _authenticate(r1, w1, "alice", PASSWORD)

        init = await _recv(r1)
        assert init["type"] == "init"
        assert init["messages"] == []

        # ── Client B connects ──────────────────────────────
        r2, w2 = await asyncio.open_connection("127.0.0.1", port)
        uid2, crypto2 = await _authenticate(r2, w2, "bob", PASSWORD)

        # A receives "user_joined" for B
        msg = await _recv(r1)
        assert msg["type"] == "user_joined"
        assert msg["username"] == "bob"

        # B receives init with A already present
        init2 = await _recv(r2)
        assert init2["type"] == "init"
        assert any(u["username"] == "alice" for u in init2["users"])

        # ── A sends encrypted message ──────────────────────
        plaintext = "Hello from Alice! 你好"
        ciphertext = crypto1.encrypt(plaintext)
        await _send(w1, {"type": "message", "text": ciphertext})

        # Both A and B receive the broadcast
        for reader, crypto in [(r1, crypto1), (r2, crypto2)]:
            msg = await _recv(reader)
            assert msg["type"] == "message"
            assert msg["data"]["username"] == "alice"
            # Server stored ciphertext, client decrypts
            decrypted = crypto.decrypt(msg["data"]["text"])
            assert decrypted == plaintext

        # ── B sends encrypted message ──────────────────────
        plaintext2 = "Reply from Bob"
        ciphertext2 = crypto2.encrypt(plaintext2)
        await _send(w2, {"type": "message", "text": ciphertext2})

        for reader, crypto in [(r1, crypto1), (r2, crypto2)]:
            msg = await _recv(reader)
            assert msg["type"] == "message"
            assert crypto.decrypt(msg["data"]["text"]) == plaintext2

        # ── Verify message indexing ────────────────────────
        assert server._messages.count == 2

        # ── B disconnects, A gets user_left ─────────────────
        w2.close()
        await w2.wait_closed()

        msg = await _recv(r1)
        assert msg["type"] == "user_left"
        assert msg["user_id"] == uid2

        w1.close()
        await w1.wait_closed()

    finally:
        tcp_server.close()
        await tcp_server.wait_closed()


@pytest.mark.asyncio
async def test_wrong_password_rejected():
    """Client with wrong password should be rejected during SRP."""
    server = ChatServer(PASSWORD)
    tcp_server = await asyncio.start_server(
        server._handle_client, "127.0.0.1", 0
    )
    port = tcp_server.sockets[0].getsockname()[1]

    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)

        usr = srp.User(SRP_IDENTITY, b"wrongpassword", hash_alg=srp.SHA256)
        _, A = usr.start_authentication()

        await _send(w, {
            "cmd": "srp_init",
            "username": "eve",
            "A": base64.b64encode(A).decode(),
        })

        resp = await _recv(r)
        B = base64.b64decode(resp["B"])
        salt = base64.b64decode(resp["salt"])

        M = usr.process_challenge(salt, B)
        if M is not None:
            await _send(w, {
                "cmd": "srp_verify",
                "user_id": resp["user_id"],
                "M": base64.b64encode(M).decode(),
            })
            resp = await _recv(r)
            assert "error" in resp

        w.close()
        await w.wait_closed()
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()


@pytest.mark.asyncio
async def test_clear_admin_only():
    """Only the first user (admin) can clear chat history."""
    server = ChatServer(PASSWORD)
    tcp_server = await asyncio.start_server(
        server._handle_client, "127.0.0.1", 0
    )
    port = tcp_server.sockets[0].getsockname()[1]

    try:
        # Alice joins first → becomes admin
        r1, w1 = await asyncio.open_connection("127.0.0.1", port)
        uid1, crypto1 = await _authenticate(r1, w1, "alice", PASSWORD)
        await _recv(r1)  # init

        # Send a message
        await _send(w1, {"type": "message", "text": crypto1.encrypt("hi")})
        await _recv(r1)  # own message broadcast
        assert server._messages.count == 1

        # Bob joins
        r2, w2 = await asyncio.open_connection("127.0.0.1", port)
        uid2, crypto2 = await _authenticate(r2, w2, "bob", PASSWORD)
        await _recv(r1)  # user_joined
        await _recv(r2)  # init

        # Bob tries to clear → should fail
        await _send(w2, {"type": "clear"})
        resp = await _recv(r2)
        assert "error" in resp
        assert server._messages.count == 1  # still has the message

        # Alice clears → should succeed
        await _send(w1, {"type": "clear"})
        cleared1 = await _recv(r1)
        cleared2 = await _recv(r2)
        assert cleared1["type"] == "cleared"
        assert cleared2["type"] == "cleared"
        assert server._messages.count == 0

        w1.close()
        w2.close()
        await w1.wait_closed()
        await w2.wait_closed()
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()
