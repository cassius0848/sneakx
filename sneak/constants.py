"""
Shared constants for sneak.

All magic numbers and cryptographic parameters live here
so they're auditable in one place.
"""

# ── Network ────────────────────────────────────────────────
DEFAULT_PORT = 8000
AUTH_TIMEOUT_SEC = 30
CONNECTION_TIMEOUT_SEC = 10

# ── Session management ─────────────────────────────────────
CLEANUP_INTERVAL_SEC = 300        # server sweeps stale sessions every 5 min
SESSION_STALE_SEC = 3600          # session expires after 1 hour of inactivity

# ── Cryptography ───────────────────────────────────────────
ROOM_SALT_BYTES = 16              # os.urandom size for room salt
AES_KEY_BYTES = 32                # AES-256
GCM_NONCE_BYTES = 12              # standard GCM nonce
MSG_SALT_BYTES = 16               # per-message random salt for key derivation

HKDF_INFO_ROOM = b"sneak-room-key"
HKDF_INFO_MSG = b"sneak-msg-key"

SRP_IDENTITY = b"chat"            # shared SRP username (room-level auth)
SRP_HASH_ALG = "SHA256"

# ── Display ────────────────────────────────────────────────
MAX_DISPLAY_MESSAGES = 15
