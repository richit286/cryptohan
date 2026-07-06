"""Konfigurasi, konstanta, dan util direktori identitas untuk CryptoHan."""

import os

from . import __version__

APP_NAME = "CryptoHan"
APP_VERSION = __version__
MAGIC = b"FCH2"
ALGO_AES, ALGO_RSA = 1, 5
ALGO_NAMES = {ALGO_AES: "AES-256-GCM", ALGO_RSA: "RSA-2048 Hybrid"}
NAME_TO_ALGO = {v: k for k, v in ALGO_NAMES.items()}

PBKDF2_ITERS = 600_000
SALT_LEN = 16
NONCE_PREFIX_LEN = 7
FILE_CHUNK = 64 * 1024

NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
NET_CHUNK = 60_000
SOCKET_TIMEOUT = 30
MAX_FILE_SIZE = 10 * 1024 ** 3
REPLAY_WINDOW_SEC = 300
DEFAULT_PORT = 50777
MAX_CONCURRENT = 8
IDENTITY_DIR = os.path.join(os.path.expanduser("~"), ".cryptohan")


class CryptoError(Exception):
    pass


class TransportError(Exception):
    pass


def ensure_identity_dir():
    os.makedirs(IDENTITY_DIR, exist_ok=True)
    try:
        os.chmod(IDENTITY_DIR, 0o700)
    except (OSError, NotImplementedError):
        pass
    return IDENTITY_DIR


def secure_chmod(path):
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass
