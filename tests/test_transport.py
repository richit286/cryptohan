import os
import socket
import threading
import time
import uuid

import pytest

from cryptohan.transport import (
    HAS_NOISE, _check_and_record, sha256_file, _safe_name, send_file, Receiver,
)
from cryptohan.keys import generate_transport_identity, load_transport_private_raw


def test_check_and_record_rejects_replay(isolated_identity_dir):
    u = uuid.uuid4().hex
    now = time.time()
    assert _check_and_record(u, now) is True
    assert _check_and_record(u, now) is False           # same uuid twice -> rejected


def test_check_and_record_rejects_stale_timestamp(isolated_identity_dir):
    u = uuid.uuid4().hex
    stale = time.time() - 10_000
    assert _check_and_record(u, stale) is False


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello world")
    import hashlib
    assert sha256_file(str(p)) == hashlib.sha256(b"hello world").hexdigest()


def test_safe_name_strips_path_and_nulls():
    assert _safe_name("../../etc/passwd") == "passwd"
    assert _safe_name("a\x00b.txt") == "ab.txt"
    assert _safe_name("") == "file.bin"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _raw_identity(tmp_path, name):
    priv = str(tmp_path / f"{name}.priv.pem")
    pub = str(tmp_path / f"{name}.pub.pem")
    generate_transport_identity(priv, pub)
    return load_transport_private_raw(priv)


@pytest.mark.skipif(not HAS_NOISE, reason="noiseprotocol tidak terpasang")
def test_send_receive_happy_path(tmp_path):
    src = tmp_path / "plain.bin"
    src.write_bytes(os.urandom(100_000))
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    sender_priv = _raw_identity(tmp_path, "sender")
    receiver_priv = _raw_identity(tmp_path, "receiver")
    port = _free_port()

    results = {}
    rcv = Receiver(port, str(out_dir), receiver_priv,
                   on_result=lambda status, info: results.update(status=status, info=info))
    t = threading.Thread(target=rcv.serve_forever, daemon=True)
    t.start()
    try:
        deadline = time.time() + 2
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

        peer_fp, size, ack = send_file("127.0.0.1", port, str(src), sender_priv)
        assert ack == "OK"
        assert size == 100_000
    finally:
        rcv.stop()
        t.join(timeout=2)

    assert results["status"] == "received"
    assert open(results["info"], "rb").read() == src.read_bytes()


@pytest.mark.skipif(not HAS_NOISE, reason="noiseprotocol tidak terpasang")
def test_mitm_abort_on_fingerprint_mismatch(tmp_path):
    src = tmp_path / "plain.bin"
    src.write_bytes(os.urandom(1000))
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    sender_priv = _raw_identity(tmp_path, "sender")
    receiver_priv = _raw_identity(tmp_path, "receiver")
    port = _free_port()

    results = {}
    rcv = Receiver(port, str(out_dir), receiver_priv,
                   on_result=lambda status, info: results.update(status=status, info=info))
    t = threading.Thread(target=rcv.serve_forever, daemon=True)
    t.start()
    try:
        deadline = time.time() + 2
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

        from cryptohan.config import TransportError
        with pytest.raises(TransportError):
            send_file("127.0.0.1", port, str(src), sender_priv, expected_fp="0" * 64)
    finally:
        rcv.stop()
        t.join(timeout=2)


@pytest.mark.skipif(not HAS_NOISE, reason="noiseprotocol tidak terpasang")
def test_sender_gets_clean_error_when_receiver_rejects_fingerprint(tmp_path):
    """Receiver menolak fingerprint pengirim -> sender harus dapat
    FingerprintMismatchError yang bersih, bukan exception socket mentah
    (BrokenPipeError/ConnectionResetError) akibat koneksi ditutup paksa."""
    src = tmp_path / "plain.bin"
    src.write_bytes(os.urandom(1000))
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    sender_priv = _raw_identity(tmp_path, "sender")
    receiver_priv = _raw_identity(tmp_path, "receiver")
    port = _free_port()

    results = {}
    rcv = Receiver(port, str(out_dir), receiver_priv, expected_fp="0" * 64,
                   on_result=lambda status, info: results.update(status=status, info=info))
    t = threading.Thread(target=rcv.serve_forever, daemon=True)
    t.start()
    try:
        deadline = time.time() + 2
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

        from cryptohan.config import FingerprintMismatchError
        with pytest.raises(FingerprintMismatchError):
            send_file("127.0.0.1", port, str(src), sender_priv)
    finally:
        rcv.stop()
        t.join(timeout=2)

    assert results["status"] == "mitm"
    assert not any(out_dir.iterdir())   # tidak ada file yang diterima/ditulis
