"""SRP (Secure Remote Password) authentication manager.

Uses RFC 5054 parameters with SHA-256. The password never crosses
the wire — both sides prove knowledge via zero-knowledge proof
and derive matching session keys.

Note: all users authenticate against the same SRP identity ("chat")
because this is room-level password auth, not per-user identity.
"""

from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4

import srp

from ..constants import SRP_IDENTITY

srp.rfc5054_enable()


@dataclass
class SRPSession:
    """Tracks a single in-progress SRP handshake."""

    user_id: str = field(default_factory=lambda: str(uuid4()))
    username: str = ""
    verifier: Optional[srp.Verifier] = None
    session_key: Optional[bytes] = None
    authenticated: bool = False


class SRPAuthManager:
    """Handles SRP registration and verification for incoming clients.

    The server pre-computes the SRP salt and verification key from
    the room password at startup. Each connecting client goes through
    a two-step handshake: init (exchange public ephemerals) then
    verify (exchange proofs).
    """

    def __init__(self, password: str):
        self._password = password.encode()
        self._sessions: dict[str, SRPSession] = {}
        self._salt, self._vkey = srp.create_salted_verification_key(
            SRP_IDENTITY, self._password, hash_alg=srp.SHA256
        )

    def init_auth(
        self, username: str, client_public: bytes
    ) -> tuple[str, bytes, bytes]:
        """Step 1: receive client's public ephemeral A, return (user_id, B, salt).

        Raises ValueError if the SRP challenge cannot be generated
        (e.g., client sent A = 0).
        """
        session = SRPSession(username=username)
        verifier = srp.Verifier(
            SRP_IDENTITY,
            self._salt,
            self._vkey,
            client_public,
            hash_alg=srp.SHA256,
        )
        s, B = verifier.get_challenge()
        if B is None:
            raise ValueError("SRP challenge generation failed (bad A?)")

        session.verifier = verifier
        self._sessions[session.user_id] = session
        return session.user_id, B, s

    def verify_auth(
        self, user_id: str, client_proof: bytes
    ) -> tuple[bytes, bytes]:
        """Step 2: verify client proof M, return (H_AMK, session_key).

        Raises ValueError on bad session or failed proof.
        The session is removed on failure to prevent replay.
        """
        session = self._sessions.get(user_id)
        if not session or not session.verifier:
            raise ValueError("Invalid or expired session")

        H_AMK = session.verifier.verify_session(client_proof)
        if H_AMK is None:
            del self._sessions[user_id]
            raise ValueError("Authentication failed — wrong password")

        session.session_key = session.verifier.get_session_key()
        session.authenticated = True
        return H_AMK, session.session_key

    def remove_session(self, user_id: str) -> None:
        self._sessions.pop(user_id, None)
