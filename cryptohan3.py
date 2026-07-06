#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoHan 2.0 — Enkripsi file + transfer aman (satu file, kelas profesional)
=============================================================================
Fitur keamanan:
  • Enkripsi STREAMING (chunked AEAD, tanpa memuat file ke RAM) — AES-256-GCM
    berbasis password & RSA-2048 Hybrid berbasis kunci.
  • Transport aman Noise_XX (forward secrecy + mutual auth) di atas TCP, streaming.
  • ABORT otomatis bila fingerprint peer tak cocok kontak (bukan sekadar warning).
  • Timeout di semua socket; batas ukuran file; anti-DoS ringan; multi-client.
  • Verifikasi checksum SHA-256 setelah transfer (file dihapus bila tak cocok).
  • Anti-replay: header ber-UUID + timestamp; UUID lama/basi ditolak.
  • Verifikasi FINGERPRINT (kata/hex/angka) untuk cegah MITM.
  • Permission file kunci 0600; contacts.json dilindungi HMAC.
  • Progress bar transfer; logging profesional (tanpa mencatat rahasia).
  • Auto-dekripsi di penerima; registry kontak IP.

Dependensi:  pip install cryptography noiseprotocol
Jalankan  :  python cryptohan.py
"""

import os
import io
import json
import time
import uuid
import struct
import socket
import hashlib
import hmac
import secrets
import threading
import logging
import logging.handlers

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

try:
    from noise.connection import NoiseConnection, Keypair
    HAS_NOISE = True
except Exception:
    HAS_NOISE = False

# ===========================================================================
#  KONFIGURASI
# ===========================================================================
APP_NAME = "CryptoHan"; APP_VERSION = "2.0"
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


class CryptoError(Exception): pass
class TransportError(Exception): pass


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


# ===========================================================================
#  LOGGING (tidak pernah mencatat password/kunci)
# ===========================================================================
_LOGGER = None


def get_logger():
    global _LOGGER
    if _LOGGER:
        return _LOGGER
    lg = logging.getLogger(APP_NAME); lg.setLevel(logging.INFO); lg.propagate = False
    path = os.path.join(ensure_identity_dir(), "cryptohan.log")
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=512 * 1024,
                                              backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                      "%Y-%m-%d %H:%M:%S"))
    lg.addHandler(fh); secure_chmod(path); _LOGGER = lg
    return lg


# ===========================================================================
#  ENKRIPSI FILE STREAMING (chunked AEAD / STREAM)
# ===========================================================================
def derive_key(password, salt, length=32):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                      iterations=PBKDF2_ITERS).derive(password.encode("utf-8"))


def _oaep():
    return asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)


def _read_exact(fp, n):
    b = fp.read(n)
    if len(b) != n:
        raise CryptoError("File terpotong / rusak.")
    return b


def _read_cfile_frame(fp):
    lb = fp.read(4)
    if len(lb) == 0:
        return None
    if len(lb) != 4:
        raise CryptoError("File terpotong (panjang frame).")
    return _read_exact(fp, struct.unpack(">I", lb)[0])


def peek_algorithm(path):
    try:
        with open(path, "rb") as f:
            hb = f.read(4)
            if len(hb) != 4:
                return None
            header = f.read(struct.unpack(">I", hb)[0])
    except OSError:
        return None
    if len(header) < 5 or header[:4] != MAGIC:
        return None
    name = ALGO_NAMES.get(header[4])
    return (header[4], name) if name else None


def encrypt_stream(in_path, out_path, algo_id, password=None, public_key=None, progress=None):
    total = os.path.getsize(in_path)
    if algo_id == ALGO_AES:
        if not password:
            raise CryptoError("Password diperlukan untuk AES.")
        salt = secrets.token_bytes(SALT_LEN); key = derive_key(password, salt); keymat = salt
    elif algo_id == ALGO_RSA:
        if public_key is None:
            raise CryptoError("Public key diperlukan untuk RSA-Hybrid.")
        key = secrets.token_bytes(32)
        enc_key = public_key.encrypt(key, _oaep())
        keymat = struct.pack(">H", len(enc_key)) + enc_key
    else:
        raise CryptoError("Algoritma tidak dikenal.")

    nonce_prefix = secrets.token_bytes(NONCE_PREFIX_LEN)
    header = MAGIC + bytes([algo_id]) + keymat + nonce_prefix
    aes = AESGCM(key)
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(struct.pack(">I", len(header)) + header)
        counter = done = 0
        prev = fin.read(FILE_CHUNK)
        while True:
            cur = fin.read(FILE_CHUNK)
            last = len(cur) == 0
            nonce = nonce_prefix + struct.pack(">I", counter) + (b"\x01" if last else b"\x00")
            ct = aes.encrypt(nonce, prev, header)
            fout.write(struct.pack(">I", len(ct)) + ct)
            done += len(prev); counter += 1
            if progress:
                progress(done, total)
            if last:
                break
            prev = cur


def decrypt_stream(in_path, out_path, password=None, private_key=None, progress=None):
    total = os.path.getsize(in_path)
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        try:
            (hlen,) = struct.unpack(">I", _read_exact(fin, 4))
            header = _read_exact(fin, hlen)
            if header[:4] != MAGIC:
                raise CryptoError("Bukan file .enc CryptoHan.")
            algo_id = header[4]; idx = 5
            if algo_id == ALGO_AES:
                if not password:
                    raise CryptoError("Perlu password untuk dekripsi.")
                salt = header[idx:idx + SALT_LEN]; idx += SALT_LEN
                key = derive_key(password, salt)
            elif algo_id == ALGO_RSA:
                if private_key is None:
                    raise CryptoError("Perlu kunci privat RSA untuk dekripsi.")
                (klen,) = struct.unpack(">H", header[idx:idx + 2]); idx += 2
                enc_key = header[idx:idx + klen]; idx += klen
                key = private_key.decrypt(enc_key, _oaep())
            else:
                raise CryptoError("Algoritma tidak dikenal.")
            nonce_prefix = header[idx:idx + NONCE_PREFIX_LEN]
            aes = AESGCM(key); counter = done = 0
            frame = _read_cfile_frame(fin)
            if frame is None:
                raise CryptoError("Tidak ada data terenkripsi.")
            while True:
                nxt = _read_cfile_frame(fin)
                last = nxt is None
                nonce = nonce_prefix + struct.pack(">I", counter) + (b"\x01" if last else b"\x00")
                try:
                    pt = aes.decrypt(nonce, frame, header)
                except Exception:
                    raise CryptoError("Password/kunci salah atau file telah diubah.")
                fout.write(pt); done += len(pt); counter += 1
                if progress:
                    progress(min(done, total), total)
                if last:
                    break
                frame = nxt
        except CryptoError:
            fout.close()
            try:
                os.remove(out_path)
            except OSError:
                pass
            raise


def decrypted_out_path(enc_path):
    base = enc_path[:-4] if enc_path.endswith(".enc") else enc_path + ".dec"
    if os.path.exists(base):
        r, e = os.path.splitext(base)
        return f"{r}_decrypted{e}"
    return base


def auto_decrypt(enc_path, password=None, private_key=None, progress=None):
    info = peek_algorithm(enc_path)
    if info is None:
        raise CryptoError("Bukan file .enc CryptoHan.")
    algo_id, name = info
    out = decrypted_out_path(enc_path)
    if algo_id == ALGO_RSA:
        decrypt_stream(enc_path, out, private_key=private_key, progress=progress)
    else:
        decrypt_stream(enc_path, out, password=password, progress=progress)
    return name, out


# ===========================================================================
#  KUNCI (RSA + X25519) — permission 0600
# ===========================================================================
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


# ===========================================================================
#  FINGERPRINT
# ===========================================================================
WORDS = [
    "able","acid","aged","army","atom","aunt","back","bake","band","bare","barn","base","bath","bean","bear","beat",
    "beef","bell","belt","bend","best","bird","bite","blue","boat","body","bold","bolt","bone","book","boot","born",
    "boss","both","bowl","brave","bread","brick","broom","brown","brush","bulk","bull","bump","bunk","burn","bush","busy",
    "cake","calm","camp","cane","card","care","cart","case","cash","cave","cell","chat","chef","chin","chip","city",
    "clap","claw","clay","clip","club","coal","coat","code","coin","cold","cook","cool","cord","core","cork","corn",
    "cost","crab","crew","crop","crow","cube","curl","dark","dawn","deal","deck","deep","deer","desk","dial","dice",
    "dine","dish","dive","dock","dome","door","dose","dove","down","drag","draw","drip","drop","drum","duck","dull",
    "dust","duty","each","earn","east","easy","edge","epic","even","ever","exit","face","fact","fade","fair","fall",
    "fame","farm","fast","fate","fear","feed","feel","fern","file","fill","film","find","fine","fire","firm","fish",
    "five","flag","flap","flat","flee","flew","flip","flow","foam","fold","folk","font","food","foot","fork","form",
    "fort","four","free","frog","fuel","full","fund","gain","game","gate","gear","gift","girl","give","glad","glow",
    "glue","goal","goat","gold","golf","gone","good","gray","grid","grim","grin","grip","grow","gulf","hair","half",
    "hall","hand","hang","hard","harm","hawk","haze","head","heal","heap","hear","heat","herb","herd","hero","hide",
    "high","hill","hint","hive","hold","hole","holy","home","hood","hook","hope","horn","host","hour","huge","hull",
    "hunt","hurt","hush","icon","idea","inch","iron","item","jade","jail","jazz","join","joke","jump","june","junk",
    "keen","keep","kick","kind","king","kiss","kite","knee","knot","lace","lack","lady","lake","lamp","lane","last",
]
assert len(WORDS) == 256 and len(set(WORDS)) == 256


def fp_digest(pb): return hashlib.sha256(pb).digest()
def fp_hex_full(pb): return fp_digest(pb).hex()
def fp_words(pb, n=8): return " ".join(WORDS[b] for b in fp_digest(pb)[:n])


def fp_hex(pb, nbytes=16, group=2):
    h = fp_digest(pb)[:nbytes].hex().upper()
    return " ".join(h[i:i + group * 2] for i in range(0, len(h), group * 2))


def fp_numeric(pb, nbytes=8, group=5):
    d = str(int.from_bytes(fp_digest(pb)[:nbytes], "big")).zfill(nbytes * 3)
    return " ".join(d[i:i + group] for i in range(0, len(d), group))


def fp_card(pb):
    return (f"  Kata    : {fp_words(pb)}\n"
            f"  Hex     : {fp_hex(pb)}\n"
            f"  Numerik : {fp_numeric(pb)}")


def fp_key_card(path, password=None):
    return fp_card(canonical_public_bytes(path, password))


# ===========================================================================
#  KONTAK (HMAC-protected)
# ===========================================================================
def _contacts_path(): return os.path.join(ensure_identity_dir(), "contacts.json")
def _mac_path(): return os.path.join(ensure_identity_dir(), "contacts.mac")


def _mac_key():
    p = os.path.join(ensure_identity_dir(), "local_mac.key")
    if not os.path.exists(p):
        with open(p, "wb") as f:
            f.write(secrets.token_bytes(32))
        secure_chmod(p)
    with open(p, "rb") as f:
        return f.read()


def _compute_mac(data): return hmac.new(_mac_key(), data, hashlib.sha256).hexdigest()


def load_contacts():
    p = _contacts_path()
    if not os.path.exists(p):
        return [], True
    try:
        with open(p, "rb") as f:
            raw = f.read()
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, list):
            return [], False
    except Exception:
        return [], False
    ok = True
    if os.path.exists(_mac_path()):
        try:
            with open(_mac_path()) as f:
                ok = hmac.compare_digest(f.read().strip(), _compute_mac(raw))
        except Exception:
            ok = False
    return data, ok


def save_contacts(contacts):
    raw = json.dumps(contacts, indent=2, ensure_ascii=False).encode("utf-8")
    with open(_contacts_path(), "wb") as f:
        f.write(raw)
    secure_chmod(_contacts_path())
    with open(_mac_path(), "w") as f:
        f.write(_compute_mac(raw))
    secure_chmod(_mac_path())


def upsert_contact(name, ip, port, fingerprint=None):
    contacts, _ = load_contacts()
    for c in contacts:
        if c.get("name") == name:
            c["ip"] = ip; c["port"] = int(port)
            if fingerprint:
                c["fingerprint"] = fingerprint
            save_contacts(contacts); return contacts
    e = {"name": name, "ip": ip, "port": int(port)}
    if fingerprint:
        e["fingerprint"] = fingerprint
    contacts.append(e); save_contacts(contacts); return contacts


def remove_contact(name):
    contacts, _ = load_contacts()
    contacts = [c for c in contacts if c.get("name") != name]
    save_contacts(contacts); return contacts


# ===========================================================================
#  TRANSPORT (Noise_XX streaming + checksum + anti-replay + abort)
# ===========================================================================
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
            raise TransportError("Fingerprint penerima TIDAK cocok kontak — abort (MITM?).")
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
                self.on_result("mitm", peer_fp); return   # ABORT, tak terima file

            header = json.loads(n.decrypt(_recv_frame(conn)).decode("utf-8"))
            size = int(header["size"]); sha_expected = str(header["sha256"])
            uuid_hex = str(header["uuid"]); ts = float(header["ts"])
            fname = _safe_name(header["name"])
            if size < 0 or size > MAX_FILE_SIZE:
                _send_frame(conn, n.encrypt(b"ERR:size"))
                self.on_result("error", "Ukuran file ditolak."); return
            if not _check_and_record(uuid_hex, ts):
                _send_frame(conn, n.encrypt(b"ERR:replay"))
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


# ===========================================================================
#  ANTARMUKA GRAFIS
# ===========================================================================
def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog

    log = get_logger()
    BG = "#1e1e2e"; FG = "#cdd6f4"; ACCENT = "#89b4fa"
    PANEL = "#313244"; OK = "#a6e3a1"; ERR = "#f38ba8"; MUTED = "#9399b2"

    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION} — Enkripsi & Transfer Aman")
    root.geometry("660x812"); root.configure(bg=BG); root.resizable(False, False)
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("TCombobox", fieldbackground=PANEL, background=PANEL)
    style.configure("CH.Horizontal.TProgressbar", troughcolor=PANEL,
                    background=ACCENT, borderwidth=0)

    mode_var = tk.StringVar(value="encrypt"); algo_var = tk.StringVar(value="AES-256-GCM")
    infile_var = tk.StringVar(); keyfile_var = tk.StringVar(); show_pw = tk.BooleanVar()
    ip_var = tk.StringVar(value="127.0.0.1"); port_var = tk.StringVar(value=str(DEFAULT_PORT))
    contact_var = tk.StringVar(); autodec_var = tk.BooleanVar(value=True)
    net = {"recv": None, "thread": None, "last_peer_fp": None, "last_pct": -1}
    contacts_by_name = {}

    def lbl(p, t, **kw): return tk.Label(p, text=t, bg=BG, fg=FG, font=("Segoe UI", 10), **kw)
    def ui(fn): root.after(0, fn)

    tk.Label(root, text="🔐  CryptoHan", bg=BG, fg=ACCENT,
             font=("Segoe UI", 17, "bold")).pack(pady=(12, 0))
    tk.Label(root, text="streaming • forward secrecy • checksum • anti-MITM • anti-replay",
             bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(pady=(0, 8))

    body = tk.Frame(root, bg=BG); body.pack(fill="x", padx=24)
    lbl(body, "Mode:").grid(row=0, column=0, sticky="w", pady=4)
    mf = tk.Frame(body, bg=BG); mf.grid(row=0, column=1, sticky="w")
    tk.Radiobutton(mf, text="Enkripsi", variable=mode_var, value="encrypt", bg=BG, fg=FG,
                   selectcolor=PANEL, activebackground=BG,
                   command=lambda: on_mode_change()).pack(side="left", padx=(0, 12))
    tk.Radiobutton(mf, text="Dekripsi", variable=mode_var, value="decrypt", bg=BG, fg=FG,
                   selectcolor=PANEL, activebackground=BG,
                   command=lambda: on_mode_change()).pack(side="left")

    algo_lbl = lbl(body, "Algoritma:"); algo_lbl.grid(row=1, column=0, sticky="w", pady=4)
    algo_combo = ttk.Combobox(body, textvariable=algo_var, state="readonly",
                              values=list(ALGO_NAMES.values()), width=28)
    algo_combo.grid(row=1, column=1, sticky="w")
    algo_combo.bind("<<ComboboxSelected>>", lambda e: refresh())
    detect_hint = tk.Label(body, text="", bg=BG, fg=ACCENT, font=("Segoe UI", 8),
                           wraplength=230, justify="left")
    detect_hint.grid(row=1, column=2, sticky="w", padx=4)

    lbl(body, "File:").grid(row=2, column=0, sticky="w", pady=4)
    ff = tk.Frame(body, bg=BG); ff.grid(row=2, column=1, sticky="w")
    tk.Entry(ff, textvariable=infile_var, width=30, bg=PANEL, fg=FG, insertbackground=FG,
             relief="flat").pack(side="left", ipady=3)
    tk.Button(ff, text="Pilih…", command=lambda: pick_infile(), bg=PANEL, fg=FG,
              relief="flat").pack(side="left", padx=6)

    pw_lbl = lbl(body, "Password:"); pw_lbl.grid(row=3, column=0, sticky="w", pady=4)
    pw_entry = tk.Entry(body, width=30, show="•", bg=PANEL, fg=FG, insertbackground=FG, relief="flat")
    pw_entry.grid(row=3, column=1, sticky="w", ipady=3)
    tk.Checkbutton(body, text="Tampilkan", variable=show_pw, bg=BG, fg=MUTED, selectcolor=PANEL,
                   activebackground=BG,
                   command=lambda: pw_entry.config(show="" if show_pw.get() else "•")
                   ).grid(row=3, column=2, sticky="w", padx=4)

    key_lbl = lbl(body, "File kunci:"); key_lbl.grid(row=4, column=0, sticky="w", pady=4)
    kf = tk.Frame(body, bg=BG); kf.grid(row=4, column=1, sticky="w")
    tk.Entry(kf, textvariable=keyfile_var, width=30, bg=PANEL, fg=FG, insertbackground=FG,
             relief="flat").pack(side="left", ipady=3)
    tk.Button(kf, text="Pilih…", command=lambda: pick_keyfile(), bg=PANEL, fg=FG,
              relief="flat").pack(side="left", padx=6)
    key_hint = tk.Label(body, text="", bg=BG, fg=MUTED, font=("Segoe UI", 8))
    key_hint.grid(row=5, column=1, sticky="w")

    keygen_btn = tk.Button(body, text="🔑 Buat Kunci RSA", command=lambda: do_keygen(),
                           bg=PANEL, fg=ACCENT, relief="flat")
    keygen_btn.grid(row=6, column=1, sticky="w", pady=(2, 2))
    tk.Button(body, text="🔎 Fingerprint / Verifikasi Kunci…", command=lambda: do_fingerprint(),
              bg=PANEL, fg=ACCENT, relief="flat").grid(row=7, column=1, sticky="w", pady=(2, 4))

    tk.Button(root, text="ENKRIPSI / DEKRIPSI", command=lambda: do_run(), bg=ACCENT, fg=BG,
              font=("Segoe UI", 11, "bold"), relief="flat", padx=14, pady=6).pack(pady=4)

    # ---- panel transfer ----
    tf = tk.LabelFrame(root, text=" Kirim langsung ke IP (kedua sisi online) ",
                       bg=BG, fg=FG, font=("Segoe UI", 9))
    tf.pack(fill="x", padx=24, pady=(2, 4))
    cr = tk.Frame(tf, bg=BG); cr.pack(fill="x", padx=8, pady=(6, 2))
    tk.Label(cr, text="Kontak:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side="left")
    contact_combo = ttk.Combobox(cr, textvariable=contact_var, state="readonly", width=15)
    contact_combo.pack(side="left", padx=(4, 6))
    contact_combo.bind("<<ComboboxSelected>>", lambda e: on_contact_selected())
    tk.Button(cr, text="＋ Simpan", command=lambda: do_save_contact(), bg=PANEL, fg=ACCENT,
              relief="flat").pack(side="left")
    tk.Button(cr, text="🗑", command=lambda: do_delete_contact(), bg=PANEL, fg=MUTED,
              relief="flat").pack(side="left", padx=4)

    ir = tk.Frame(tf, bg=BG); ir.pack(fill="x", padx=8, pady=2)
    tk.Label(ir, text="IP penerima:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side="left")
    tk.Entry(ir, textvariable=ip_var, width=16, bg=PANEL, fg=FG, insertbackground=FG,
             relief="flat").pack(side="left", padx=(4, 10), ipady=2)
    tk.Label(ir, text="Port:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side="left")
    tk.Entry(ir, textvariable=port_var, width=7, bg=PANEL, fg=FG, insertbackground=FG,
             relief="flat").pack(side="left", padx=(4, 0), ipady=2)

    br = tk.Frame(tf, bg=BG); br.pack(fill="x", padx=8, pady=(2, 4))
    send_btn = tk.Button(br, text="📤 Kirim .enc…", command=lambda: do_send(), bg=PANEL,
                         fg=ACCENT, relief="flat"); send_btn.pack(side="left")
    recv_btn = tk.Button(br, text="📥 Mulai terima", command=lambda: do_receive(), bg=PANEL,
                         fg=ACCENT, relief="flat"); recv_btn.pack(side="left", padx=8)
    tk.Checkbutton(br, text="🔓 Auto-dekripsi", variable=autodec_var, bg=BG, fg=FG,
                   selectcolor=PANEL, activebackground=BG).pack(side="left", padx=4)

    pr = tk.Frame(tf, bg=BG); pr.pack(fill="x", padx=8, pady=(0, 8))
    progress_bar = ttk.Progressbar(pr, style="CH.Horizontal.TProgressbar",
                                   length=400, maximum=100)
    progress_bar.pack(side="left", fill="x", expand=True)
    progress_lbl = tk.Label(pr, text="idle", bg=BG, fg=MUTED, font=("Consolas", 8), width=18)
    progress_lbl.pack(side="left", padx=6)

    log_box = tk.Text(root, height=8, bg="#11111b", fg=FG, relief="flat",
                      font=("Consolas", 9), wrap="word")
    log_box.pack(fill="both", expand=True, padx=24, pady=(0, 12))
    log_box.config(state="disabled")

    def write_log(msg, color=FG, level="info"):
        log_box.config(state="normal"); log_box.tag_config(color, foreground=color)
        log_box.insert("end", msg + "\n", color); log_box.see("end")
        log_box.config(state="disabled")
        getattr(log, level if level in ("info", "warning", "error") else "info")(
            msg.replace("\n", " | "))

    def set_progress(done, total):
        pct = int(done * 100 / total) if total else 100
        if pct != net["last_pct"]:
            net["last_pct"] = pct
            ui(lambda: (progress_bar.config(value=pct),
                        progress_lbl.config(text=f"{done//1024}/{total//1024}KB {pct}%")))

    # ---------------- enkripsi/dekripsi ----------------
    def on_mode_change():
        infile_var.set(""); keyfile_var.set(""); pw_entry.delete(0, "end"); refresh()

    def pick_infile():
        if mode_var.get() == "decrypt":
            p = filedialog.askopenfilename(title="Pilih file .enc",
                    filetypes=[("File terenkripsi", "*.enc"), ("Semua", "*.*")])
        else:
            p = filedialog.askopenfilename(title="Pilih file untuk dienkripsi")
        if p:
            infile_var.set(p); refresh()

    def pick_keyfile():
        p = filedialog.askopenfilename(title="Pilih file kunci (.pem)",
                filetypes=[("Kunci PEM", "*.pem"), ("Semua", "*.*")])
        if not p:
            return
        keyfile_var.set(p)
        try:
            write_log("Fingerprint kunci ini — cocokkan dengan lawan:\n" +
                      fp_key_card(p, password=pw_entry.get().strip() or None), ACCENT)
        except Exception:
            pass

    def _show_inputs_for(algo_id):
        if algo_id is None:
            for w in (pw_lbl, pw_entry):
                w.grid_remove()
            key_lbl.grid_remove(); kf.grid_remove(); keygen_btn.grid_remove(); key_hint.grid_remove()
            return
        is_rsa = algo_id == ALGO_RSA
        for w in (pw_lbl, pw_entry):
            w.grid() if not is_rsa else w.grid_remove()
        key_lbl.grid() if is_rsa else key_lbl.grid_remove()
        kf.grid() if is_rsa else kf.grid_remove()
        keygen_btn.grid() if (is_rsa and mode_var.get() == "encrypt") else keygen_btn.grid_remove()
        if is_rsa:
            key_hint.config(text=("Untuk enkripsi: pilih PUBLIC key" if mode_var.get() == "encrypt"
                                  else "Untuk dekripsi: pilih PRIVATE key")); key_hint.grid()
        else:
            key_hint.grid_remove()

    def refresh():
        if mode_var.get() == "encrypt":
            algo_combo.config(state="readonly"); algo_lbl.config(fg=FG)
            detect_hint.grid_remove(); _show_inputs_for(NAME_TO_ALGO[algo_var.get()]); return
        algo_combo.config(state="disabled")
        path = infile_var.get().strip()
        info = peek_algorithm(path) if (path and os.path.isfile(path)) else None
        if info:
            algo_id, name = info; algo_var.set(name); algo_lbl.config(fg=FG)
            detect_hint.config(text="✓ terbaca otomatis dari file", fg=OK); detect_hint.grid()
            _show_inputs_for(algo_id)
        else:
            algo_lbl.config(fg="#6c7086")
            detect_hint.config(text=("⚠ bukan file .enc CryptoHan" if path else "pilih file .enc dulu →"),
                               fg=(ERR if path else MUTED)); detect_hint.grid(); _show_inputs_for(None)

    def do_keygen():
        folder = filedialog.askdirectory(title="Simpan kunci di folder…")
        if not folder:
            return
        priv = os.path.join(folder, "cryptohan.priv.pem")
        pub = os.path.join(folder, "cryptohan.pub.pem")
        try:
            generate_rsa_keypair(priv, pub, password=pw_entry.get().strip() or None)
            card = fp_key_card(pub)
            write_log(f"✓ Kunci dibuat (priv 0600):\n   {priv}\n   {pub}", OK)
            write_log("Fingerprint kunci publik (bacakan ke lawan):\n" + card, ACCENT)
            messagebox.showinfo("Sukses", "Pasangan kunci RSA dibuat.\n\nFingerprint publik:\n" + card)
        except Exception as e:
            write_log(f"✗ Gagal buat kunci: {e}", ERR, "error")

    def do_fingerprint():
        p = filedialog.askopenfilename(title="Pilih file kunci (.pem)",
                filetypes=[("Kunci PEM", "*.pem"), ("Semua", "*.*")])
        if not p:
            return
        try:
            card = fp_key_card(p, password=pw_entry.get().strip() or None)
            write_log(f"Fingerprint {os.path.basename(p)}:\n" + card, ACCENT)
            messagebox.showinfo("Fingerprint", card +
                "\n\nBandingkan dgn lawan lewat jalur lain. COCOK=asli, BEDA=MITM.")
        except Exception as e:
            write_log(f"✗ Gagal fingerprint: {e}", ERR, "error")
            messagebox.showerror("Gagal", f"{e}\n\nJika privat terenkripsi, isi Password.")

    def do_run():
        in_path = infile_var.get().strip()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showwarning("Perhatian", "Pilih file input valid dulu."); return
        mode = mode_var.get()
        try:
            if mode == "encrypt":
                algo_id = NAME_TO_ALGO[algo_var.get()]; out_path = in_path + ".enc"
                if algo_id == ALGO_RSA:
                    kp = keyfile_var.get().strip()
                    if not kp:
                        messagebox.showwarning("Perhatian", "Pilih PUBLIC key dulu."); return
                    encrypt_stream(in_path, out_path, algo_id, public_key=load_public_key(kp),
                                   progress=set_progress)
                else:
                    pw = pw_entry.get()
                    if not pw:
                        messagebox.showwarning("Perhatian", "Isi password dulu."); return
                    encrypt_stream(in_path, out_path, algo_id, password=pw, progress=set_progress)
                write_log(f"✓ Terenkripsi [{algo_var.get()}] → {out_path}", OK)
                messagebox.showinfo("Sukses", f"File dienkripsi:\n{out_path}")
            else:
                info = peek_algorithm(in_path)
                if info is None:
                    messagebox.showerror("Gagal", "Bukan file .enc CryptoHan."); return
                algo_id, _ = info; out_path = decrypted_out_path(in_path)
                if algo_id == ALGO_RSA:
                    kp = keyfile_var.get().strip()
                    if not kp:
                        messagebox.showwarning("Perhatian", "Pilih PRIVATE key dulu."); return
                    priv = load_private_key(kp, password=pw_entry.get().strip() or None)
                    decrypt_stream(in_path, out_path, private_key=priv, progress=set_progress)
                else:
                    pw = pw_entry.get()
                    if not pw:
                        messagebox.showwarning("Perhatian", "Isi password dulu."); return
                    decrypt_stream(in_path, out_path, password=pw, progress=set_progress)
                write_log(f"✓ Terdekripsi → {out_path}", OK)
                messagebox.showinfo("Sukses", f"File didekripsi:\n{out_path}")
        except Exception as e:
            write_log(f"✗ Gagal: {e}", ERR, "error"); messagebox.showerror("Gagal", str(e))

    # ---------------- kontak ----------------
    def refresh_contacts():
        contacts_by_name.clear()
        data, ok = load_contacts()
        if not ok:
            write_log("⚠ contacts.json gagal verifikasi integritas (HMAC) — diabaikan.", ERR, "warning")
            data = []
        for c in data:
            contacts_by_name[c["name"]] = c
        contact_combo["values"] = list(contacts_by_name.keys())

    def on_contact_selected():
        c = contacts_by_name.get(contact_var.get())
        if c:
            ip_var.set(c.get("ip", "")); port_var.set(str(c.get("port", "")))
            if c.get("fingerprint"):
                write_log(f"Kontak '{c['name']}' punya fingerprint — verifikasi otomatis aktif.", MUTED)

    def do_save_contact():
        name = simpledialog.askstring("Simpan kontak", "Nama kontak:", parent=root)
        if not name:
            return
        try:
            port = int(port_var.get())
        except ValueError:
            messagebox.showwarning("Perhatian", "Port harus angka."); return
        fp = net.get("last_peer_fp")
        upsert_contact(name.strip(), ip_var.get().strip(), port, fingerprint=fp)
        refresh_contacts(); contact_var.set(name.strip())
        write_log(f"Kontak '{name.strip()}' disimpan{' (+ fingerprint)' if fp else ''}.", OK)

    def do_delete_contact():
        name = contact_var.get().strip()
        if name and messagebox.askyesno("Hapus", f"Hapus kontak '{name}'?"):
            remove_contact(name); refresh_contacts(); contact_var.set("")
            write_log(f"Kontak '{name}' dihapus.", MUTED)

    # ---------------- transfer ----------------
    def _peer_handler(who, pinned_fp, cname):
        def h(peer_raw):
            fpx = fp_hex_full(peer_raw); net["last_peer_fp"] = fpx; card = fp_card(peer_raw)
            if pinned_fp:
                if hmac.compare_digest(pinned_fp, fpx):
                    ui(lambda: write_log(f"✓ {who} TERVERIFIKASI (cocok kontak '{cname}').", OK))
                else:
                    ui(lambda: write_log(f"⚠ BAHAYA: fingerprint {who} tak cocok — abort.", ERR, "warning"))
            else:
                ui(lambda: write_log(f"Fingerprint {who} (verifikasi lewat jalur luar):\n{card}", ACCENT))
        return h

    def do_send():
        if not HAS_NOISE:
            messagebox.showerror("Butuh library", "pip install noiseprotocol"); return
        host = ip_var.get().strip() or "127.0.0.1"
        try:
            port = int(port_var.get())
        except ValueError:
            messagebox.showwarning("Perhatian", "Port harus angka."); return
        fp = filedialog.askopenfilename(title="Pilih file .enc untuk dikirim",
                filetypes=[("File terenkripsi", "*.enc"), ("Semua", "*.*")])
        if not fp:
            return
        cname = contact_var.get().strip()
        pinned = (contacts_by_name.get(cname) or {}).get("fingerprint")
        priv_path, _ = ensure_transport_identity()
        mypriv = load_transport_private_raw(priv_path)
        net["last_pct"] = -1

        def worker():
            try:
                ui(lambda: write_log(f"Menghubungi {host}:{port}…", ACCENT))
                peer_fp, size, ack = send_file(host, port, fp, mypriv, expected_fp=pinned,
                        on_peer=_peer_handler("PENERIMA", pinned, cname), progress=set_progress)
                ui(lambda: write_log(f"✓ Terkirim {size} byte (ack: {ack})", OK if ack == "OK" else ERR))
                ui(lambda: messagebox.showinfo("Terkirim",
                    f"File terkirim ({size} byte).\nStatus penerima: {ack}"))
            except Exception as e:
                ui(lambda: write_log(f"✗ Gagal kirim: {e}", ERR, "error"))
                ui(lambda: messagebox.showerror("Gagal kirim", str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def do_receive():
        if not HAS_NOISE:
            messagebox.showerror("Butuh library", "pip install noiseprotocol"); return
        if net["recv"] is not None:                 # sudah listen -> berhenti
            net["recv"].stop(); net["recv"] = None
            recv_btn.config(text="📥 Mulai terima"); write_log("Berhenti menerima.", MUTED); return
        try:
            port = int(port_var.get())
        except ValueError:
            messagebox.showwarning("Perhatian", "Port harus angka."); return
        outdir = filedialog.askdirectory(title="Simpan file diterima di folder…")
        if not outdir:
            return
        cname = contact_var.get().strip()
        pinned = (contacts_by_name.get(cname) or {}).get("fingerprint")
        priv_path, _ = ensure_transport_identity()
        mypriv = load_transport_private_raw(priv_path)
        my_fp = fp_card(transport_public_raw_from_private(mypriv))
        net["last_pct"] = -1

        def on_result(status, info):
            if status == "received":
                ui(lambda: after_receive(info))
            elif status == "mitm":
                ui(lambda: write_log("⚠ Koneksi DITOLAK: fingerprint pengirim tak cocok kontak (MITM?).", ERR, "warning"))
            elif status == "replay":
                ui(lambda: write_log(f"⚠ {info}", ERR, "warning"))
            elif status == "checksum_fail":
                ui(lambda: write_log(f"⚠ {info}", ERR, "warning"))
            else:
                ui(lambda: write_log(f"✗ {info}", ERR, "error"))

        rcv = Receiver(port, outdir, mypriv, expected_fp=pinned,
                       on_peer=_peer_handler("PENGIRIM", pinned, cname),
                       on_progress=set_progress, on_result=on_result)
        net["recv"] = rcv
        t = threading.Thread(target=rcv.serve_forever, daemon=True); t.start()
        net["thread"] = t
        recv_btn.config(text="■ Berhenti terima")
        write_log(f"Menunggu di port {port} (multi-client aktif)…\n"
                  f"Fingerprint transport Anda (untuk pengirim):\n{my_fp}", ACCENT)

    def after_receive(enc_path):
        write_log(f"✓ File diterima (checksum OK) → {enc_path}", OK)
        if not autodec_var.get():
            messagebox.showinfo("Diterima", f"Tersimpan:\n{enc_path}\n(Auto-dekripsi mati.)"); return
        info = peek_algorithm(enc_path)
        if info is None:
            messagebox.showinfo("Diterima", f"Tersimpan (bukan .enc):\n{enc_path}"); return
        algo_id, name = info
        try:
            if algo_id == ALGO_RSA:
                kp = keyfile_var.get().strip()
                if not kp:
                    kp = filedialog.askopenfilename(
                        title="RSA-Hybrid diterima — pilih PRIVATE key untuk dekripsi",
                        filetypes=[("Kunci PEM", "*.pem"), ("Semua", "*.*")])
                    if not kp:
                        write_log("Auto-dekripsi dilewati (tanpa kunci privat).", MUTED); return
                priv = load_private_key(kp, password=pw_entry.get().strip() or None)
                dn, out = auto_decrypt(enc_path, private_key=priv, progress=set_progress)
            else:
                pw = pw_entry.get() or simpledialog.askstring(
                    "Password", f"File {name} diterima. Password untuk dekripsi:", show="•", parent=root)
                if not pw:
                    write_log("Auto-dekripsi dilewati (tanpa password).", MUTED); return
                dn, out = auto_decrypt(enc_path, password=pw, progress=set_progress)
            write_log(f"✓ Auto-dekripsi [{dn}] → {out}", OK)
            messagebox.showinfo("Auto-dekripsi sukses", f"File didekripsi:\n{out}")
        except Exception as e:
            write_log(f"✗ Auto-dekripsi gagal: {e}", ERR, "error")
            messagebox.showerror("Auto-dekripsi gagal", f"{e}\n\nFile .enc tetap:\n{enc_path}")

    def on_close():
        if net["recv"] is not None:
            net["recv"].stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh(); refresh_contacts()
    write_log(f"{APP_NAME} {APP_VERSION} siap. Log: {os.path.join(IDENTITY_DIR, 'cryptohan.log')}", ACCENT)
    if not HAS_NOISE:
        write_log("Fitur transfer nonaktif — pasang: pip install noiseprotocol", MUTED, "warning")
    log.info("Aplikasi dijalankan.")
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
