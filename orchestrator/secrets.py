"""Encryption at rest for the one thing erlik must hold and must not leak.

A pentest tool has to log in, so it has to hold a client's password. Three
rules follow, and each is enforced somewhere in this module or asserted in
tests/test_credentials.py:

  THE KEY IS NEVER IN THE DATABASE. It lives in ERLIK_SECRET_KEY, or in a file
  beside the database created 0600 on first use. A key stored next to the
  ciphertext it protects is a filing decision, not encryption — anyone who can
  read the database can read the secret.

  NOTHING RETURNS A SECRET. `decrypt` exists for exactly one caller: the login
  executor, at the moment it authenticates. Everything an operator can read
  goes through `masked()`, and the API never serialises `secret_enc`.

  A MISSING KEY IS A REFUSAL, NOT A FALLBACK. If the key cannot be loaded,
  storing a credential FAILS. Quietly falling back to plaintext would be the
  worst possible behaviour: it looks identical from the outside and it is the
  failure the whole module exists to prevent.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

KEY_ENV = "ERLIK_SECRET_KEY"
KEY_FILE = Path(os.environ.get("ERLIK_SECRET_KEY_FILE",
                               Path(__file__).resolve().parent.parent
                               / "data" / ".secret_key"))

MASK = "••••••••"


class SecretError(RuntimeError):
    """The key is unavailable, so a secret cannot be stored or read."""


def _load_key() -> bytes:
    env = os.environ.get(KEY_ENV, "").strip()
    if env:
        return env.encode()
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes().strip()
    # First use: mint one, 0600, before anything is written to it. Created with
    # restrictive permissions from the start rather than chmod'd afterwards —
    # the gap between the two is a readable key.
    try:
        KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
        print(f"[secrets] generated a new key at {KEY_FILE} (0600). Back it up: "
              f"losing it makes stored credentials unreadable.", flush=True)
        return key
    except FileExistsError:
        return KEY_FILE.read_bytes().strip()
    except OSError as e:
        raise SecretError(f"cannot create a key at {KEY_FILE}: {e}") from e


def _fernet() -> Fernet:
    try:
        return Fernet(_load_key())
    except SecretError:
        raise
    except Exception as e:  # malformed key
        raise SecretError(
            f"{KEY_ENV} is not a valid Fernet key ({e}). Generate one with "
            f"`python -c \"from cryptography.fernet import Fernet; "
            f"print(Fernet.generate_key().decode())\"`.") from e


def encrypt(plaintext: str) -> str:
    """Ciphertext for storage. Raises rather than storing anything readable."""
    if plaintext is None:
        raise SecretError("refusing to encrypt None")
    return _fernet().encrypt(str(plaintext).encode()).decode()


def decrypt(ciphertext: str | None) -> str:
    """Plaintext, for the single moment of use. Never log or return this."""
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as e:
        raise SecretError(
            "stored credential cannot be decrypted — the key has changed or "
            "the row was written under a different one") from e


def masked(_ciphertext: str | None = None) -> str:
    """What an operator sees. Fixed width on purpose: a mask whose length
    tracks the secret leaks the secret's length."""
    return MASK


def is_encrypted(value: str | None) -> bool:
    """True if this looks like something `encrypt` produced.

    Used by a test that walks the live database asserting no credential column
    ever holds readable text.
    """
    if not value:
        return False
    try:
        _fernet().decrypt(value.encode())
        return True
    except Exception:
        return False
