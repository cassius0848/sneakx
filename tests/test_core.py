"""Tests for sneak crypto, models, and stores."""

import os
import pytest
from sneak.crypto import derive_room_key, MessageCrypto
from sneak.server.models import Message, UserSession
from sneak.server.stores import MessageStore, UserSessionStore
from sneak.server.srp_auth import SRPAuthManager
from sneak.constants import AES_KEY_BYTES


# ── Crypto tests ───────────────────────────────────────────


class TestDeriveRoomKey:
    def test_deterministic(self):
        """Same password + salt → same key."""
        salt = os.urandom(16)
        k1 = derive_room_key(b"secret", salt)
        k2 = derive_room_key(b"secret", salt)
        assert k1 == k2

    def test_different_password(self):
        salt = os.urandom(16)
        k1 = derive_room_key(b"secret", salt)
        k2 = derive_room_key(b"other", salt)
        assert k1 != k2

    def test_different_salt(self):
        k1 = derive_room_key(b"secret", os.urandom(16))
        k2 = derive_room_key(b"secret", os.urandom(16))
        assert k1 != k2

    def test_key_length(self):
        key = derive_room_key(b"secret", os.urandom(16))
        assert len(key) == AES_KEY_BYTES


class TestMessageCrypto:
    @pytest.fixture
    def crypto(self):
        key = derive_room_key(b"testpassword", os.urandom(16))
        return MessageCrypto(key)

    def test_roundtrip(self, crypto):
        plaintext = "Hello, world! 你好世界"
        token = crypto.encrypt(plaintext)
        assert crypto.decrypt(token) == plaintext

    def test_different_ciphertext_each_time(self, crypto):
        """Per-message random salt → different ciphertext."""
        t1 = crypto.encrypt("same message")
        t2 = crypto.encrypt("same message")
        assert t1 != t2

    def test_wrong_key_fails(self):
        key1 = derive_room_key(b"password1", os.urandom(16))
        key2 = derive_room_key(b"password2", os.urandom(16))
        c1 = MessageCrypto(key1)
        c2 = MessageCrypto(key2)
        token = c1.encrypt("secret")
        with pytest.raises(Exception):  # InvalidTag
            c2.decrypt(token)

    def test_tampered_ciphertext_fails(self, crypto):
        token = crypto.encrypt("hello")
        # Flip a byte in the middle
        raw = bytearray(token.encode())
        raw[len(raw) // 2] ^= 0xFF
        with pytest.raises(Exception):
            crypto.decrypt(bytes(raw).decode())

    def test_empty_string(self, crypto):
        token = crypto.encrypt("")
        assert crypto.decrypt(token) == ""

    def test_long_message(self, crypto):
        msg = "x" * 10_000
        assert crypto.decrypt(crypto.encrypt(msg)) == msg

    def test_bad_key_length(self):
        with pytest.raises(ValueError):
            MessageCrypto(b"tooshort")

    def test_wipe(self, crypto):
        crypto.wipe()
        assert crypto._room_key == b"\x00" * AES_KEY_BYTES


# ── Model tests ────────────────────────────────────────────


class TestMessage:
    def test_no_ip_field(self):
        """Message should NOT contain user_ip (metadata leak fix)."""
        m = Message(text="test", username="alice")
        assert not hasattr(m, "user_ip")

    def test_has_index(self):
        m = Message()
        assert hasattr(m, "index")
        assert m.index == 0


class TestUserSession:
    def test_no_ip_or_key(self):
        """Session should not store IP or key material."""
        s = UserSession(user_id="123")
        assert not hasattr(s, "ip")
        assert not hasattr(s, "fernet_key")

    def test_stale_detection(self):
        s = UserSession(user_id="123")
        assert not s.is_stale(timeout=3600)
        assert s.is_stale(timeout=0)


# ── Store tests ────────────────────────────────────────────


class TestMessageStore:
    def test_auto_index(self, message_store):
        m1 = message_store.add(Message(text="a"))
        m2 = message_store.add(Message(text="b"))
        assert m1.index == 0
        assert m2.index == 1

    def test_clear_preserves_counter(self, message_store):
        """Clear removes messages but doesn't reset counter (prevents key reuse)."""
        message_store.add(Message(text="a"))
        message_store.add(Message(text="b"))
        message_store.clear()
        m3 = message_store.add(Message(text="c"))
        assert m3.index == 2

    def test_get_all_is_copy(self, message_store):
        message_store.add(Message(text="x"))
        msgs = message_store.get_all()
        msgs.clear()
        assert message_store.count == 1


class TestUserSessionStore:
    def test_add_and_get(self, session_store):
        s = UserSession(user_id="abc", username="alice")
        session_store.add(s)
        assert session_store.get("abc") is s

    def test_username_exists(self, session_store):
        session_store.add(UserSession(user_id="1", username="alice"))
        assert session_store.username_exists("alice")
        assert not session_store.username_exists("bob")

    def test_remove(self, session_store):
        session_store.add(UserSession(user_id="1", username="alice"))
        session_store.remove("1")
        assert session_store.get("1") is None

    def test_cleanup_stale(self, session_store):
        session_store.add(UserSession(user_id="1"))
        removed = session_store.cleanup_stale(timeout=0)
        assert removed == 1
        assert session_store.count == 0


# ── SRP tests ──────────────────────────────────────────────


class TestSRPAuth:
    def test_full_handshake(self, srp_manager):
        """Complete SRP handshake with correct password succeeds."""
        import srp as srplib
        srplib.rfc5054_enable()

        usr = srplib.User(b"chat", b"testpassword", hash_alg=srplib.SHA256)
        _, A = usr.start_authentication()

        user_id, B, salt = srp_manager.init_auth("testuser", A)
        M = usr.process_challenge(salt, B)
        assert M is not None

        H_AMK, session_key = srp_manager.verify_auth(user_id, M)
        usr.verify_session(H_AMK)
        assert usr.authenticated()

    def test_wrong_password_fails(self, srp_manager):
        import srp as srplib
        srplib.rfc5054_enable()

        usr = srplib.User(b"chat", b"wrongpassword", hash_alg=srplib.SHA256)
        _, A = usr.start_authentication()

        user_id, B, salt = srp_manager.init_auth("baduser", A)
        M = usr.process_challenge(salt, B)
        # M might be None or verification will fail
        if M is not None:
            with pytest.raises(ValueError, match="failed"):
                srp_manager.verify_auth(user_id, M)

    def test_invalid_session(self, srp_manager):
        with pytest.raises(ValueError):
            srp_manager.verify_auth("nonexistent", b"fakeproof")
