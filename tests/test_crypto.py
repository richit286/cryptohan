import os

import pytest

from cryptohan.config import ALGO_AES, ALGO_RSA, CryptoError
from cryptohan.crypto import (
    encrypt_stream, decrypt_stream, peek_algorithm, decrypted_out_path,
)
from cryptohan.keys import load_public_key, load_private_key


def _make_plain(tmp_path, size=200_000):
    p = tmp_path / "plain.bin"
    p.write_bytes(os.urandom(size))
    return str(p)


def test_aes_roundtrip(tmp_path):
    src = _make_plain(tmp_path)
    enc = str(tmp_path / "a.enc")
    out = str(tmp_path / "a.out")
    encrypt_stream(src, enc, ALGO_AES, password="s3cret")
    decrypt_stream(enc, out, password="s3cret")
    assert open(src, "rb").read() == open(out, "rb").read()


def test_aes_wrong_password(tmp_path):
    src = _make_plain(tmp_path)
    enc = str(tmp_path / "a.enc")
    out = str(tmp_path / "a.out")
    encrypt_stream(src, enc, ALGO_AES, password="s3cret")
    with pytest.raises(CryptoError):
        decrypt_stream(enc, out, password="wrong")


def test_aes_tampered_ciphertext(tmp_path):
    src = _make_plain(tmp_path, size=300_000)
    enc = tmp_path / "a.enc"
    out = str(tmp_path / "a.out")
    encrypt_stream(src, str(enc), ALGO_AES, password="s3cret")
    data = bytearray(enc.read_bytes())
    data[-50] ^= 0xFF
    enc.write_bytes(bytes(data))
    with pytest.raises(CryptoError):
        decrypt_stream(str(enc), out, password="s3cret")


def test_aes_truncated_file(tmp_path):
    src = _make_plain(tmp_path)
    enc = tmp_path / "a.enc"
    out = str(tmp_path / "a.out")
    encrypt_stream(src, str(enc), ALGO_AES, password="s3cret")
    truncated = enc.read_bytes()[:10]
    enc.write_bytes(truncated)
    with pytest.raises(CryptoError):
        decrypt_stream(str(enc), out, password="s3cret")


def test_rsa_roundtrip(tmp_path, rsa_keypair):
    priv_path, pub_path = rsa_keypair
    src = _make_plain(tmp_path)
    enc = str(tmp_path / "r.enc")
    out = str(tmp_path / "r.out")
    encrypt_stream(src, enc, ALGO_RSA, public_key=load_public_key(pub_path))
    decrypt_stream(enc, out, private_key=load_private_key(priv_path))
    assert open(src, "rb").read() == open(out, "rb").read()


def test_peek_algorithm(tmp_path, rsa_keypair):
    priv_path, pub_path = rsa_keypair
    src = _make_plain(tmp_path, size=1000)
    enc_aes = str(tmp_path / "a.enc")
    enc_rsa = str(tmp_path / "r.enc")
    encrypt_stream(src, enc_aes, ALGO_AES, password="pw")
    encrypt_stream(src, enc_rsa, ALGO_RSA, public_key=load_public_key(pub_path))

    assert peek_algorithm(enc_aes) == (ALGO_AES, "AES-256-GCM")
    assert peek_algorithm(enc_rsa) == (ALGO_RSA, "RSA-2048 Hybrid")
    assert peek_algorithm(src) is None                      # bukan file .enc
    assert peek_algorithm(str(tmp_path / "missing.enc")) is None

    empty = tmp_path / "empty.enc"
    empty.write_bytes(b"")
    assert peek_algorithm(str(empty)) is None

    truncated_header = tmp_path / "trunc.enc"
    truncated_header.write_bytes(b"\x00\x00")
    assert peek_algorithm(str(truncated_header)) is None


def test_decrypted_out_path_avoids_collision(tmp_path):
    enc = tmp_path / "file.enc"
    enc.write_bytes(b"")
    base = tmp_path / "file"
    base.write_bytes(b"already here")
    out = decrypted_out_path(str(enc))
    assert out == str(tmp_path / "file_decrypted")
