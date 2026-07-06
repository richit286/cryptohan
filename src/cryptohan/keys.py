"""Kunci (RSA + X25519) — permission 0600."""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .config import ensure_identity_dir, secure_chmod


def _enc(password):
    return (serialization.BestAvailableEncryption(password.encode())
            if password else serialization.NoEncryption())


def generate_rsa_keypair(priv_path, pub_path, password=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(priv_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, _enc(password)))
    secure_chmod(priv_path)
    with open(pub_path, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path, password=None):
    with open(path, "rb") as f:
        pw = password.encode() if password else None
        return serialization.load_pem_private_key(f.read(), password=pw)


def canonical_public_bytes(path, password=None):
    with open(path, "rb") as f:
        data = f.read()
    try:
        pub = serialization.load_pem_public_key(data)
    except Exception:
        pw = password.encode() if password else None
        pub = serialization.load_pem_private_key(data, password=pw).public_key()
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def generate_transport_identity(priv_path, pub_path, password=None):
    p = X25519PrivateKey.generate()
    with open(priv_path, "wb") as f:
        f.write(p.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, _enc(password)))
    secure_chmod(priv_path)
    with open(pub_path, "wb") as f:
        f.write(p.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))


def load_transport_private_raw(path, password=None):
    with open(path, "rb") as f:
        pw = password.encode() if password else None
        priv = serialization.load_pem_private_key(f.read(), password=pw)
    return priv.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption())


def transport_public_raw_from_private(priv_raw):
    return X25519PrivateKey.from_private_bytes(priv_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ensure_transport_identity():
    d = ensure_identity_dir()
    priv = os.path.join(d, "transport.priv.pem")
    pub = os.path.join(d, "transport.pub.pem")
    if not (os.path.exists(priv) and os.path.exists(pub)):
        generate_transport_identity(priv, pub)
    secure_chmod(priv)
    return priv, pub


def _default_privkey_pointer_path():
    return os.path.join(ensure_identity_dir(), "default_privkey.path")


def get_default_privkey():
    """Path kunci privat RSA yang terakhir dipin sebagai default, atau None
    bila belum pernah diset atau file-nya sudah tak ada lagi di disk."""
    try:
        with open(_default_privkey_pointer_path(), encoding="utf-8") as f:
            path = f.read().strip()
    except OSError:
        return None
    return path if path and os.path.isfile(path) else None


def set_default_privkey(path):
    pointer = _default_privkey_pointer_path()
    with open(pointer, "w", encoding="utf-8") as f:
        f.write(path)
    secure_chmod(pointer)
