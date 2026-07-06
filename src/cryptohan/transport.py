"""Transport aman (Noise_XX streaming + checksum + anti-replay + abort).

Setelah handshake Noise_XX selesai, kedua pihak sudah tahu fingerprint statis
lawan bicara. Sebelum satu byte data file pun dikirim, penerima mengirim
frame terenkripsi ACCEPT/REJECT berdasarkan hasil pengecekan fingerprint
pengirim terhadap `expected_fp` miliknya, dan pengirim WAJIB membaca frame
itu sebelum mengirim header/isi file. Ini mencegah dua hal:
  1) file terkirim ke pihak yang penerima sendiri sudah tolak (boros +
     berisiko bila lawan bicara ternyata MITM aktif dengan handshake valid),
  2) pengirim mendapat exception socket mentah (bukan pesan error yang jelas)
     ketika penerima menutup koneksi karena fingerprint tak cocok.
"""

import os
import json
import time
import uuid
import struct
import socket
import hashlib
import hmac
import threading

try:
    from noise.connection import NoiseConnection, Keypair
    HAS_NOISE = True
except Exception:
    HAS_NOISE = False

from .config import (
    NOISE_NAME, NET_CHUNK, SOCKET_TIMEOUT, MAX_FILE_SIZE, REPLAY_WINDOW_SEC,
    MAX_CONCURRENT, FILE_CHUNK, TransportError, FingerprintMismatchError, ensure_identity_dir,
)
from .fingerprint import fp_hex_full
from .logging_setup import get_logger


def _send_frame(sock, data): sock.sendall(struct.pack(">I", len(data)) + data)


def _recvn(sock, n):
    b = bytearray()
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c:
            raise TransportError("koneksi terputus")
        b += c
    return bytes(b)


def _recv_frame(sock): return _recvn(sock, struct.unpack(">I", _recvn(sock, 4))[0])


def _rs_public_raw(hs):
    rs = getattr(hs, "rs", None)
    v = getattr(rs, "public_bytes", None) if rs is not None else None
    return bytes(v) if isinstance(v, (bytes, bytearray)) else None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(FILE_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_name(name):
    return os.path.basename(str(name)).replace("\x00", "") or "file.bin"


_seen_lock = threading.Lock()
def _seen_path(): return os.path.join(ensure_identity_dir(), "seen.json")


def _load_seen():
    try:
        with open(_seen_path()) as f:
            return json.load(f)
    except Exception:
        return {}


def _check_and_record(uuid_hex, ts):
    now = time.time()
    if abs(now - ts) > REPLAY_WINDOW_SEC:
        return False
    with _seen_lock:
        seen = {u: t for u, t in _load_seen().items() if now - t < REPLAY_WINDOW_SEC}
        if uuid_hex in seen:
            return False
        seen[uuid_hex] = now
        try:
            with open(_seen_path(), "w") as f:
                json.dump(seen, f)
        except Exception:
            pass
    return True


def send_file(host, port, file_path, static_priv_raw,
              expected_fp=None, on_peer=None, progress=None):
    """Kirim streaming. expected_fp -> ABORT bila tak cocok. Return (fp,size,ack)."""
    if not HAS_NOISE:
        raise TransportError("Library 'noiseprotocol' belum terpasang.")
    size = os.path.getsize(file_path)
    if size > MAX_FILE_SIZE:
        raise TransportError("Ukuran file melebihi batas maksimum.")
    sha = sha256_file(file_path)
    s = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
    s.settimeout(SOCKET_TIMEOUT)
    try:
        n = NoiseConnection.from_name(NOISE_NAME); n.set_as_initiator()
        n.set_keypair_from_private_bytes(Keypair.STATIC, static_priv_raw)
        n.start_handshake(); hs = n.noise_protocol.handshake_state
        _send_frame(s, n.write_message())
        n.read_message(_recv_frame(s))
        _send_frame(s, n.write_message())
        peer = _rs_public_raw(hs); peer_fp = fp_hex_full(peer)
        if on_peer:
            on_peer(peer)
        if expected_fp and not hmac.compare_digest(expected_fp, peer_fp):
            get_logger().warning(
                f"SECURITY fingerprint_mismatch role=sender remote={host}:{port} peer_fp={peer_fp}")
            raise FingerprintMismatchError("Fingerprint penerima TIDAK cocok kontak — abort (MITM?).")

        reply = n.decrypt(_recv_frame(s))
        if reply != b"ACCEPT":
            get_logger().warning(
                f"SECURITY peer_rejected role=sender remote={host}:{port} peer_fp={peer_fp} reply={reply!r}")
            raise FingerprintMismatchError(
                "Penerima MENOLAK koneksi: fingerprint pengirim tak cocok kontak (MITM?).")

        header = {"name": _safe_name(file_path), "size": size, "sha256": sha,
                  "uuid": uuid.uuid4().hex, "ts": time.time()}
        _send_frame(s, n.encrypt(json.dumps(header).encode("utf-8")))
        sent = 0
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(NET_CHUNK)
                if not chunk:
                    break
                _send_frame(s, n.encrypt(chunk)); sent += len(chunk)
                if progress:
                    progress(sent, size)
        ack = n.decrypt(_recv_frame(s)).decode("utf-8", "replace")
        return peer_fp, size, ack
    finally:
        s.close()


class Receiver:
    """Server penerima multi-client. serve_forever() di thread; stop() untuk henti."""

    def __init__(self, port, out_dir, static_priv_raw, expected_fp=None,
                 on_peer=None, on_progress=None, on_result=None):
        self.port = port; self.out_dir = out_dir
        self.static_priv_raw = static_priv_raw; self.expected_fp = expected_fp
        self.on_peer = on_peer or (lambda *_: None)
        self.on_progress = on_progress or (lambda *_: None)
        self.on_result = on_result or (lambda *_: None)
        self._stop = False

    def stop(self): self._stop = True

    def serve_forever(self):
        if not HAS_NOISE:
            self.on_result("error", "Library 'noiseprotocol' belum terpasang."); return
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.port)); srv.listen(MAX_CONCURRENT); srv.settimeout(1.0)
        try:
            while not self._stop:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        finally:
            srv.close()

    def _handle(self, conn, addr):
        conn.settimeout(SOCKET_TIMEOUT); out_path = None
        try:
            n = NoiseConnection.from_name(NOISE_NAME); n.set_as_responder()
            n.set_keypair_from_private_bytes(Keypair.STATIC, self.static_priv_raw)
            n.start_handshake(); hs = n.noise_protocol.handshake_state
            n.read_message(_recv_frame(conn))
            _send_frame(conn, n.write_message())
            n.read_message(_recv_frame(conn))
            peer = _rs_public_raw(hs); peer_fp = fp_hex_full(peer)
            self.on_peer(peer)
            if self.expected_fp and not hmac.compare_digest(self.expected_fp, peer_fp):
                get_logger().warning(
                    f"SECURITY fingerprint_mismatch role=receiver remote={addr[0]}:{addr[1]} peer_fp={peer_fp}")
                _send_frame(conn, n.encrypt(b"REJECT:fingerprint"))
                self.on_result("mitm", peer_fp); return   # ABORT, tak terima file
            _send_frame(conn, n.encrypt(b"ACCEPT"))

            header = json.loads(n.decrypt(_recv_frame(conn)).decode("utf-8"))
            size = int(header["size"]); sha_expected = str(header["sha256"])
            uuid_hex = str(header["uuid"]); ts = float(header["ts"])
            fname = _safe_name(header["name"])
            if size < 0 or size > MAX_FILE_SIZE:
                _send_frame(conn, n.encrypt(b"ERR:size"))
                get_logger().warning(f"SECURITY size_rejected remote={addr[0]}:{addr[1]} peer_fp={peer_fp}")
                self.on_result("error", "Ukuran file ditolak."); return
            if not _check_and_record(uuid_hex, ts):
                _send_frame(conn, n.encrypt(b"ERR:replay"))
                get_logger().warning(f"SECURITY replay_rejected remote={addr[0]}:{addr[1]} peer_fp={peer_fp}")
                self.on_result("replay", "Ditolak (replay / timestamp basi)."); return

            out_path = os.path.join(self.out_dir, fname)
            if os.path.exists(out_path):
                r, e = os.path.splitext(out_path); out_path = f"{r}_{uuid_hex[:6]}{e}"
            h = hashlib.sha256(); received = 0
            with open(out_path, "wb") as f:
                while received < size:
                    chunk = n.decrypt(_recv_frame(conn))
                    if received + len(chunk) > size:
                        chunk = chunk[:size - received]
                    f.write(chunk); h.update(chunk); received += len(chunk)
                    self.on_progress(received, size)
            if not hmac.compare_digest(h.hexdigest(), sha_expected):
                try:
                    os.remove(out_path)
                except OSError:
                    pass
                _send_frame(conn, n.encrypt(b"ERR:checksum"))
                get_logger().warning(f"SECURITY checksum_mismatch remote={addr[0]}:{addr[1]} peer_fp={peer_fp}")
                self.on_result("checksum_fail", "Checksum tak cocok — file dihapus."); return
            _send_frame(conn, n.encrypt(b"OK"))
            self.on_result("received", out_path)
        except Exception as e:
            if out_path and os.path.exists(out_path):
                try:
                    os.remove(out_path)
                except OSError:
                    pass
            self.on_result("error", str(e))
        finally:
            try:
                conn.close()
            except OSError:
                pass
