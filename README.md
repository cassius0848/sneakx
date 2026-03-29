# sneakx

Encrypted tin-can telephone.

One file. Copy anywhere. Run immediately.

## Quick start

```bash
# Start a room
python sneakx.py serve -p mysecret

# Join from another machine
python sneakx.py join 192.168.1.5 alice -p mysecret
```

Password can also be set via `SNEAKX_PASSWORD` env var, or omit `-p` to get an interactive prompt.

Requires: `pip install cryptography srp rich`

## Options

```bash
python sneakx.py serve -p mysecret --ttl 60      # messages burn after 60s
python sneakx.py serve -p mysecret --ttl 0        # persist until server stops
python sneakx.py serve -p mysecret --idle 600     # auto-shutdown after 10min idle
python sneakx.py serve -p mysecret --port 3000    # custom port
```

## In chat

- Type and press Enter to send
- `/clear` — wipe history (admin only, auto-transfers on disconnect)
- `/q` — disconnect

## How it works

- **Password never transmitted** — SRP zero-knowledge proof
- **End-to-end encrypted** — AES-256-GCM, per-message HKDF key derivation
- **Anti-replay** — ciphertext dedup on server + sequence AAD in GCM
- **Server is blind** — relays ciphertext, reads nothing
- **Ephemeral** — messages burn after TTL, everything destroyed on stop

## Security hardening (19 vulnerabilities fixed across 2 audit rounds)

| # | Threat | Mitigation |
|---|--------|-----------|
| 1 | SRP session flooding | Pending cap (100) + 30s TTL + periodic sweep |
| 2 | Unbounded readline OOM | StreamReader limit (2 MB) on server + client |
| 3 | Message size bomb | 1 MB ciphertext cap per message |
| 4 | MITM attack | SRP mutual auth (H_AMK) verifies both sides |
| 5 | Message replay | Server-side ciphertext hash dedup + AAD seq in GCM |
| 6 | No forward secrecy per-msg | Per-message HKDF salt → unique AES key each message |
| 7 | Key material in memory | ctypes memset wipe on disconnect + shutdown |
| 8 | Brute-force auth | Per-IP rate limit (10/min) with memory cap |
| 9 | Password in process list | `-p` flag / env var / interactive prompt |
| 10 | Username spoofing | Strict regex: `[a-zA-Z0-9_-]{1,20}` |
| 11 | Rich markup injection | `rich.markup.escape()` on all display text |
| 12 | os._exit skipping cleanup | Graceful async shutdown via CancelledError |
| 13 | Auto-install supply chain | Removed — explicit pip install required |
| 14 | Group chat broken by session binding | Room key uses (password, room_salt) only — shared across clients |
| 15 | safe_readline data loss | Replaced with asyncio StreamReader.limit parameter |
| 16 | JSON parse crash | try/except + continue on JSONDecodeError |
| 17 | Slowloris DoS | Max 50 concurrent TCP connections |
| 18 | Rate limit memory leak | Stale IP pruning + hard cap at 10k entries |
| 19 | Admin lost on disconnect | Auto-transfer to next active user |

## Credits
. MIT License.
