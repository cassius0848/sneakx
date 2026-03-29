"""In-memory stores for messages and user sessions."""

from typing import Optional

from .models import Message, UserSession
from ..constants import SESSION_STALE_SEC


class MessageStore:
    """Thread-safe in-memory message store with monotonic indexing."""

    def __init__(self):
        self._messages: list[Message] = []
        self._next_index: int = 0

    def add(self, message: Message) -> Message:
        """Append a message, assigning the next global index."""
        message.index = self._next_index
        self._next_index += 1
        self._messages.append(message)
        return message

    def get_all(self) -> list[Message]:
        return self._messages.copy()

    def clear(self) -> None:
        self._messages.clear()
        # intentionally don't reset _next_index to avoid key reuse

    @property
    def count(self) -> int:
        return len(self._messages)


class UserSessionStore:
    """Manages active user sessions."""

    def __init__(self):
        self._sessions: dict[str, UserSession] = {}

    def add(self, session: UserSession) -> None:
        self._sessions[session.user_id] = session

    def get(self, user_id: str) -> Optional[UserSession]:
        return self._sessions.get(user_id)

    def update_activity(self, user_id: str) -> None:
        if session := self._sessions.get(user_id):
            session.update_activity()

    def remove(self, user_id: str) -> None:
        self._sessions.pop(user_id, None)

    def cleanup_stale(self, timeout: int = SESSION_STALE_SEC) -> int:
        """Remove sessions inactive for `timeout` seconds. Returns count removed."""
        stale = [uid for uid, s in self._sessions.items() if s.is_stale(timeout)]
        for uid in stale:
            del self._sessions[uid]
        return len(stale)

    def get_all(self) -> list[UserSession]:
        return list(self._sessions.values())

    @property
    def count(self) -> int:
        return len(self._sessions)

    def username_exists(self, username: str) -> bool:
        return any(s.username == username for s in self._sessions.values())
