# sneak

End-to-end encrypted terminal chat over TCP, with SRP (Secure Remote Password) authentication.

> Based on [emilycodestar/cmd-chat](https://github.com/emilycodestar/cmd-chat). Rebuilt with security fixes, upgraded cryptography, and cleaner code.

## Features

- **Zero-knowledge password auth** — SRP protocol means the password is never transmitted
- **End-to-end encryption** — server stores only ciphertext, cannot read messages
- **AES-256-GCM** — authenticated encryption with per-message key derivation
- **Mutual authentication** — both client and server prove knowledge of the password
- **No metadata leaks** — client IP is not stored in message records

## Install

```bash
git clone https://github.com/cassius0848/sneakx.git
cd sneak
python -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

Windows:
```
python -m venv venv & venv\Scripts\activate & pip install -r requirements.txt
```

## Usage

Start server:
```bash
python sneak.py serve 0.0.0.0 3000 --password mysecret
```

Connect:
```bash
python sneak.py connect SERVER_IP 3000 username mysecret
```

In-chat commands:
- `/clear` — clear chat history (admin only)
- `/q` — disconnect

## Architecture

```
sneak/
├── __init__.py          # CLI entry point
├── constants.py         # All config in one place
├── crypto.py            # AES-256-GCM + HKDF key derivation
├── client/
│   └── client.py        # Terminal UI (Rich) + SRP handshake
└── server/
    ├── server.py         # Async TCP server + auth + message relay
    ├── srp_auth.py       # SRP session management
    ├── models.py         # Message / UserSession dataclasses
    ├── stores.py         # In-memory message + session stores
    └── managers.py       # Connection tracking + broadcast
```

## Security model

```
password ──┬──► SRP ──► mutual auth (password never transmitted)
           │
           └──► HKDF(password, room_salt) ──► room_key
                                                │
                                  per message:  │
                                  HKDF(room_key, random_salt) ──► msg_key
                                                                    │
                                                        AES-256-GCM encrypt
```

**Key properties:**
- Password never crosses the wire (SRP zero-knowledge proof)
- room_key is derived client-side, server never sees it
- Each message uses a fresh random salt → unique AES key per message
- GCM provides both confidentiality and integrity (tampered messages are rejected)
- Server stores only ciphertext; no IP addresses in message records

**Known limitations:**
- Compromising the room password allows decryption of all messages (shared-secret model)
- No per-user identity verification beyond SRP (all users share one password)
- True forward secrecy would require a ratcheting protocol (e.g., Signal Sender Keys)
- In-memory only — server restart loses all messages

## Tests

```bash
python -m pytest tests/ -v
```

29 tests covering crypto, models, stores, SRP handshake, and full TCP integration.

## Credits

Original project by [emilycodestar](https://github.com/emilycodestar/cmd-chat) (MIT License).

## License

MIT
