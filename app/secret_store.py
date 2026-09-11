import os
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


CREDENTIAL_KEY_FILE = Path(
    os.getenv("CREDENTIAL_KEY_FILE", "/run/secrets/backup_monitor_credential_keys")
)
BACKUP_KEY_FILE = Path(
    os.getenv("BACKUP_KEY_FILE", "/run/secrets/backup_monitor_backup_keys")
)


def _read_keys(path):
    try:
        keys = [line.strip() for line in path.read_text(encoding="ascii").splitlines() if line.strip()]
    except OSError as exc:
        raise RuntimeError(f"Encryption key file unavailable: {path}") from exc
    if not keys:
        raise RuntimeError(f"Encryption key file is empty: {path}")
    try:
        return MultiFernet([Fernet(key.encode("ascii")) for key in keys])
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Invalid encryption key file: {path}") from exc


@lru_cache(maxsize=1)
def credential_cipher():
    return _read_keys(CREDENTIAL_KEY_FILE)


@lru_cache(maxsize=1)
def backup_cipher():
    return _read_keys(BACKUP_KEY_FILE)


def encrypt_secret(value):
    if value is None or value == "":
        return None
    return credential_cipher().encrypt(str(value).encode("utf-8")).decode("ascii")


def decrypt_secret(value):
    if value is None or value == "":
        return None
    try:
        return credential_cipher().decrypt(str(value).encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("Encrypted credential could not be decrypted") from exc


def encrypt_backup(data):
    return backup_cipher().encrypt(data)


def decrypt_backup(data):
    try:
        return backup_cipher().decrypt(data)
    except InvalidToken as exc:
        raise RuntimeError("Encrypted backup could not be decrypted") from exc
