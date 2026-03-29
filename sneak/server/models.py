"""Data models for server-side state."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from ..constants import SESSION_STALE_SEC


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Message:
    """A stored chat message.

    The server only sees ciphertext in `text`.
    No client IP is stored — that would be a metadata leak
    in an E2EE system.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    text: str = ""                    # ciphertext (server cannot read)
    timestamp: str = field(default_factory=_utc_now)
    username: str = ""
    index: int = 0                    # global monotonic message counter


@dataclass
class UserSession:
    """Tracks an authenticated user's connection state."""

    user_id: str
    username: str = "unknown"
    created_at: str = field(default_factory=_utc_now)
    last_activity: str = field(default_factory=_utc_now)
    active: bool = True
    # NOTE: no IP, no key material stored in session

    def update_activity(self):
        self.last_activity = _utc_now()

    def is_stale(self, timeout: int = SESSION_STALE_SEC) -> bool:
        last = datetime.fromisoformat(self.last_activity)
        return (datetime.now(timezone.utc) - last).total_seconds() > timeout
