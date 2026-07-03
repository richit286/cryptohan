#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoHan - Enkripsi + Fingerprint + Kirim Langsung (LAN) + Auto-Dekripsi
==========================================================================
Fitur:
  1. Enkripsi/dekripsi file: AES-256-GCM & RSA-2048 Hybrid.
  2. Verifikasi FINGERPRINT kunci (anti-MITM).
  3. KONTAK: daftarkan & simpan alamat IP penerima (nama, IP, port, fingerprint).
  4. KIRIM LANGSUNG ke IP penerima lewat channel Noise_XX (forward secrecy + auth),
     kedua sisi online berbarengan.
  5. AUTO-DEKRIPSI di sisi penerima begitu file tiba (RSA-Hybrid: pakai kunci
     privat penerima; AES: minta password).

Dependensi:
    pip install cryptography            (wajib)
    pip install noiseprotocol           (untuk Kirim Langsung)

Format .enc:  [4B 'FCH1'][1B algo_id][payload]
"""

import os
import json
import struct
import secrets
import hashlib
import hmac
import socket
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

try:
    from noise.connection import NoiseConnection, Keypair
    _HAS_NOISE = True
except Exception:
    _HAS_NOISE = False

# ---------------------------------------------------------------------------
MAGIC = b"FCH1"
PBKDF2_ITERS = 600_000
SALT_LEN = 16
ALGORITHMS = {"AES-256-GCM": 1, "RSA-2048 Hybrid": 5}
ALGO_BY_ID = {v: k for k, v in ALGORITHMS.items()}
PASSWORD_ALGOS = {1}
KEY_ALGOS = {5}


# ---------------------------------------------------------------------------
# PBKDF2 + ENKRIPSI/DEKRIPSI
# ---------------------------------------------------------------------------
def derive_key(password, salt, length):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                      iterations=PBKDF2_ITERS).derive(password.encode("utf-8"))


def _enc_aes_gcm(data, password):
    salt = secrets.token_bytes(SALT_LEN); nonce = secrets.token_bytes(12)
    ct = AESGCM(derive_key(password, salt, 32)).encrypt(nonce, data, None)
    return salt + nonce + ct


def _enc_rsa_hybrid(data, public_key):
    aes_key = secrets.token_bytes(32); nonce = secrets.token_bytes(12)
    ct = AESGCM(aes_key).encrypt(nonce, data, None)
    enc_key = public_key.encrypt(aes_key, asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return struct.pack(">H", len(enc_key)) + enc_key + nonce + ct


def _dec_aes_gcm(payload, password):
    salt, nonce, ct = payload[:16], payload[16:28], payload[28:]
    return AESGCM(derive_key(password, salt, 32)).decrypt(nonce, ct, None)


def _dec_rsa_hybrid(payload, private_key):
    (klen,) = struct.unpack(">H", payload[:2])
    enc_key = payload[2:2 + klen]; rest = payload[2 + klen:]
    nonce, ct = rest[:12], rest[12:]
    aes_key = private_key.decrypt(enc_key, asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return AESGCM(aes_key).decrypt(nonce, ct, None)


def encrypt_file(in_path, out_path, algo_name, password=None, public_key=None):
    algo_id = ALGORITHMS[algo_name]
    with open(in_path, "rb") as f:
        data = f.read()
    if algo_id == 1:
        payload = _enc_aes_gcm(data, password)
    elif algo_id == 5:
        payload = _enc_rsa_hybrid(data, public_key)
    else:
        raise ValueError("Algoritma tidak dikenal")
    with open(out_path, "wb") as f:
        f.write(MAGIC + bytes([algo_id]) + payload)


def decrypt_file(in_path, out_path, password=None, private_key=None):
    with open(in_path, "rb") as f:
        blob = f.read()
    if blob[:4] != MAGIC:
        raise ValueError("File bukan hasil enkripsi CryptoHan (header tidak cocok).")
    algo_id = blob[4]; payload = blob[5:]
    algo_name = ALGO_BY_ID.get(algo_id, f"ID {algo_id}")
    if algo_id == 1:
        data = _dec_aes_gcm(payload, password)
    elif algo_id == 5:
        data = _dec_rsa_hybrid(payload, private_key)
    else:
        raise ValueError("Algoritma di file tidak dikenal.")
    with open(out_path, "wb") as f:
        f.write(data)
    return algo_name


def peek_algorithm(path):
    try:
        with open(path, "rb") as f:
            head = f.read(5)
    except OSError:
        return None
    if len(head) < 5 or head[:4] != MAGIC:
        return None
    name = ALGO_BY_ID.get(head[4])
    return (head[4], name) if name else None


def _decrypted_out_path(enc_path):
    base = enc_path[:-4] if enc_path.endswith(".enc") else enc_path + ".dec"
    if os.path.exists(base):
        r, e = os.path.splitext(base)
        return f"{r}_decrypted{e}"
    return base


def auto_decrypt(enc_path, password=None, private_key=None):
    """Dekripsi otomatis sesuai algoritma yang terbaca dari header file."""
    info = peek_algorithm(enc_path)
    if info is None:
        raise ValueError("Bukan file .enc CryptoHan yang valid.")
    algo_id, name = info
    out_path = _decrypted_out_path(enc_path)
    if algo_id in KEY_ALGOS:
        if private_key is None:
            raise ValueError("Perlu kunci privat RSA untuk dekripsi.")
        decrypt_file(enc_path, out_path, private_key=private_key)
    else:
        if not password:
            raise ValueError("Perlu password untuk dekripsi.")
        decrypt_file(enc_path, out_path, password=password)
    return name, out_path


# ---------------------------------------------------------------------------
# KUNCI RSA
# ---------------------------------------------------------------------------
def generate_rsa_keypair(priv_path, pub_path, password=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    with open(priv_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, enc))
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
assert len(WORDS) == 256 and len(set(WORDS)) == 256, "WORDLIST harus 256 kata unik"


def _canonical_public_bytes(path, password=None):
    with open(path, "rb") as f:
        data = f.read()
    try:
        pub = serialization.load_pem_public_key(data)
    except Exception:
        pw = password.encode() if password else None
        pub = serialization.load_pem_private_key(data, password=pw).public_key()
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint_digest(pub_bytes): return hashlib.sha256(pub_bytes).digest()
def fp_hex_full(pub_bytes): return fingerprint_digest(pub_bytes).hex()

def fp_words(pub_bytes, nwords=8):
    return " ".join(WORDS[b] for b in fingerprint_digest(pub_bytes)[:nwords])

def fp_hex(pub_bytes, nbytes=16, group=2):
    h = fingerprint_digest(pub_bytes)[:nbytes].hex().upper()
    return " ".join(h[i:i + group * 2] for i in range(0, len(h), group * 2))

def fp_numeric(pub_bytes, nbytes=8, group=5):
    digits = str(int.from_bytes(fingerprint_digest(pub_bytes)[:nbytes], "big")).zfill(nbytes * 3)
    return " ".join(digits[i:i + group] for i in range(0, len(digits), group))

def fingerprint_card(pub_bytes):
    return (f"  Kata    : {fp_words(pub_bytes)}\n"
            f"  Hex     : {fp_hex(pub_bytes)}\n"
            f"  Numerik : {fp_numeric(pub_bytes)}")

def key_fingerprint_card(path, password=None):
    return fingerprint_card(_canonical_public_bytes(path, password))

def verify_match(a, b):
    return hmac.compare_digest(fingerprint_digest(a), fingerprint_digest(b))


# ===========================================================================
#  TRANSPORT (Noise_XX)
# ===========================================================================
NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
CHUNK = 60000


def _send_frame(sock, data): sock.sendall(struct.pack(">I", len(data)) + data)

def _recvn(sock, n):
    b = bytearray()
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c:
            raise ConnectionError("koneksi terputus")
        b += c
    return bytes(b)

def _recv_frame(sock): return _recvn(sock, struct.unpack(">I", _recvn(sock, 4))[0])

def _rs_public_raw(hs):
    rs = getattr(hs, "rs", None)
    v = getattr(rs, "public_bytes", None) if rs is not None else None
    return bytes(v) if isinstance(v, (bytes, bytearray)) else None


def generate_transport_identity(priv_path, pub_path, password=None):
    p = X25519PrivateKey.generate()
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    with open(priv_path, "wb") as f:
        f.write(p.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, enc))
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


def send_file(host, port, file_path, static_priv_raw, on_peer=None):
    with open(file_path, "rb") as f:
        data = f.read()
    fname = os.path.basename(file_path).encode("utf-8")
    s = socket.create_connection((host, port), timeout=15)
    try:
        n = NoiseConnection.from_name(NOISE_NAME); n.set_as_initiator()
        n.set_keypair_from_private_bytes(Keypair.STATIC, static_priv_raw)
        n.start_handshake(); hs = n.noise_protocol.handshake_state
        _send_frame(s, n.write_message())
        n.read_message(_recv_frame(s))
        _send_frame(s, n.write_message())
        peer = _rs_public_raw(hs)
        if on_peer:
            on_peer(peer)
        header = struct.pack(">H", len(fname)) + fname + struct.pack(">Q", len(data))
        _send_frame(s, n.encrypt(header))
        for i in range(0, len(data), CHUNK):
            _send_frame(s, n.encrypt(data[i:i + CHUNK]))
        return peer, len(data)
    finally:
        s.close()


def receive_file(port, out_dir, static_priv_raw, on_peer=None, stop_flag=None):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port)); srv.listen(1); srv.settimeout(1.0)
    conn = None
    try:
        while True:
            if stop_flag is not None and stop_flag[0]:
                return None, None
            try:
                conn, _ = srv.accept(); break
            except socket.timeout:
                continue
        n = NoiseConnection.from_name(NOISE_NAME); n.set_as_responder()
        n.set_keypair_from_private_bytes(Keypair.STATIC, static_priv_raw)
        n.start_handshake(); hs = n.noise_protocol.handshake_state
        n.read_message(_recv_frame(conn))
        _send_frame(conn, n.write_message())
        n.read_message(_recv_frame(conn))
        peer = _rs_public_raw(hs)
        if on_peer:
            on_peer(peer)
        header = n.decrypt(_recv_frame(conn))
        flen = struct.unpack(">H", header[:2])[0]
        fname = header[2:2 + flen].decode("utf-8", "replace")
        total = struct.unpack(">Q", header[2 + flen:2 + flen + 8])[0]
        buf = bytearray()
        while len(buf) < total:
            buf += n.decrypt(_recv_frame(conn))
        out_path = os.path.join(out_dir, fname)
        if os.path.exists(out_path):
            r, e = os.path.splitext(out_path); out_path = f"{r}_terkirim{e}"
        with open(out_path, "wb") as f:
            f.write(bytes(buf))
        return peer, out_path
    finally:
        if conn:
            conn.close()
        srv.close()


def _identity_dir():
    d = os.path.join(os.path.expanduser("~"), ".cryptohan")
    os.makedirs(d, exist_ok=True)
    return d


def ensure_transport_identity():
    d = _identity_dir()
    priv = os.path.join(d, "transport.priv.pem")
    pub = os.path.join(d, "transport.pub.pem")
    if not (os.path.exists(priv) and os.path.exists(pub)):
        generate_transport_identity(priv, pub)
    return priv, pub


# ===========================================================================
#  KONTAK (registry IP penerima)
# ===========================================================================
def _contacts_path(): return os.path.join(_identity_dir(), "contacts.json")


def load_contacts():
    p = _contacts_path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_contacts(contacts):
    with open(_contacts_path(), "w", encoding="utf-8") as f:
        json.dump(contacts, f, indent=2, ensure_ascii=False)


def upsert_contact(name, ip, port, fingerprint=None):
    contacts = load_contacts()
    for c in contacts:
        if c.get("name") == name:
            c["ip"] = ip; c["port"] = int(port)
            if fingerprint:
                c["fingerprint"] = fingerprint
            save_contacts(contacts)
            return contacts
    entry = {"name": name, "ip": ip, "port": int(port)}
    if fingerprint:
        entry["fingerprint"] = fingerprint
    contacts.append(entry)
    save_contacts(contacts)
    return contacts


def remove_contact(name):
    contacts = [c for c in load_contacts() if c.get("name") != name]
    save_contacts(contacts)
    return contacts


# ===========================================================================
#  ANTARMUKA GRAFIS
# ===========================================================================
def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog

    BG = "#1e1e2e"; FG = "#cdd6f4"; ACCENT = "#89b4fa"
    PANEL = "#313244"; OK = "#a6e3a1"; ERR = "#f38ba8"; MUTED = "#9399b2"

    root = tk.Tk()
    root.title("CryptoHan — Enkripsi, Kirim & Auto-Dekripsi")
    root.geometry("640x788")
    root.configure(bg=BG)
    root.resizable(False, False)
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("TCombobox", fieldbackground=PANEL, background=PANEL)

    mode_var = tk.StringVar(value="encrypt")
    algo_var = tk.StringVar(value="AES-256-GCM")
    infile_var = tk.StringVar(); keyfile_var = tk.StringVar()
    show_pw = tk.BooleanVar(value=False)
    ip_var = tk.StringVar(value="127.0.0.1"); port_var = tk.StringVar(value="50777")
    contact_var = tk.StringVar(); autodec_var = tk.BooleanVar(value=True)
    net = {"receiving": False, "stop": [False], "last_peer_fp": None}
    contacts_by_name = {}

    def lbl(parent, text, **kw):
        return tk.Label(parent, text=text, bg=BG, fg=FG, font=("Segoe UI", 10), **kw)

    def ui(fn): root.after(0, fn)

    tk.Label(root, text="🔐  CryptoHan", bg=BG, fg=ACCENT,
             font=("Segoe UI", 17, "bold")).pack(pady=(12, 0))
    tk.Label(root, text="enkripsi • fingerprint • kirim ke IP • auto-dekripsi",
             bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(pady=(0, 8))

    body = tk.Frame(root, bg=BG); body.pack(fill="x", padx=24)

    lbl(body, "Mode:").grid(row=0, column=0, sticky="w", pady=4)
    mframe = tk.Frame(body, bg=BG); mframe.grid(row=0, column=1, sticky="w")
    tk.Radiobutton(mframe, text="Enkripsi", variable=mode_var, value="encrypt",
                   bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG,
                   command=lambda: on_mode_change()).pack(side="left", padx=(0, 12))
    tk.Radiobutton(mframe, text="Dekripsi", variable=mode_var, value="decrypt",
                   bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG,
                   command=lambda: on_mode_change()).pack(side="left")

    algo_lbl = lbl(body, "Algoritma:")
    algo_lbl.grid(row=1, column=0, sticky="w", pady=4)
    algo_combo = ttk.Combobox(body, textvariable=algo_var, state="readonly",
                              values=list(ALGORITHMS.keys()), width=28)
    algo_combo.grid(row=1, column=1, sticky="w")
    algo_combo.bind("<<ComboboxSelected>>", lambda e: refresh())
    detect_hint = tk.Label(body, text="", bg=BG, fg=ACCENT,
                           font=("Segoe UI", 8), wraplength=220, justify="left")
    detect_hint.grid(row=1, column=2, sticky="w", padx=4)

    lbl(body, "File:").grid(row=2, column=0, sticky="w", pady=4)
    fframe = tk.Frame(body, bg=BG); fframe.grid(row=2, column=1, sticky="w")
    tk.Entry(fframe, textvariable=infile_var, width=30, bg=PANEL, fg=FG,
             insertbackground=FG, relief="flat").pack(side="left", ipady=3)
    tk.Button(fframe, text="Pilih…", command=lambda: pick_infile(),
              bg=PANEL, fg=FG, relief="flat").pack(side="left", padx=6)

    pw_lbl = lbl(body, "Password:")
    pw_lbl.grid(row=3, column=0, sticky="w", pady=4)
    pw_entry = tk.Entry(body, width=30, show="•", bg=PANEL, fg=FG,
                        insertbackground=FG, relief="flat")
    pw_entry.grid(row=3, column=1, sticky="w", ipady=3)
    tk.Checkbutton(body, text="Tampilkan", variable=show_pw, bg=BG, fg=MUTED,
                   selectcolor=PANEL, activebackground=BG,
                   command=lambda: pw_entry.config(show="" if show_pw.get() else "•")
                   ).grid(row=3, column=2, sticky="w", padx=4)

    key_lbl = lbl(body, "File kunci:")
    key_lbl.grid(row=4, column=0, sticky="w", pady=4)
    kframe = tk.Frame(body, bg=BG); kframe.grid(row=4, column=1, sticky="w")
    tk.Entry(kframe, textvariable=keyfile_var, width=30, bg=PANEL, fg=FG,
             insertbackground=FG, relief="flat").pack(side="left", ipady=3)
    tk.Button(kframe, text="Pilih…", command=lambda: pick_keyfile(),
              bg=PANEL, fg=FG, relief="flat").pack(side="left", padx=6)
    key_hint = tk.Label(body, text="", bg=BG, fg=MUTED, font=("Segoe UI", 8))
    key_hint.grid(row=5, column=1, sticky="w")

    keygen_btn = tk.Button(body, text="🔑 Buat Kunci RSA", command=lambda: do_keygen(),
                           bg=PANEL, fg=ACCENT, relief="flat")
    keygen_btn.grid(row=6, column=1, sticky="w", pady=(2, 2))
    fp_btn = tk.Button(body, text="🔎 Fingerprint / Verifikasi Kunci…",
                       command=lambda: do_fingerprint(), bg=PANEL, fg=ACCENT, relief="flat")
    fp_btn.grid(row=7, column=1, sticky="w", pady=(2, 4))

    run_btn = tk.Button(root, text="ENKRIPSI / DEKRIPSI", command=lambda: do_run(),
                        bg=ACCENT, fg=BG, font=("Segoe UI", 11, "bold"),
                        relief="flat", padx=14, pady=6)
    run_btn.pack(pady=4)

    # --- Kirim langsung + Kontak ---
    tf = tk.LabelFrame(root, text=" Kirim langsung ke IP (kedua sisi online) ",
                       bg=BG, fg=FG, font=("Segoe UI", 9))
    tf.pack(fill="x", padx=24, pady=(2, 4))

    crow = tk.Frame(tf, bg=BG); crow.pack(fill="x", padx=8, pady=(6, 2))
    tk.Label(crow, text="Kontak:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side="left")
    contact_combo = ttk.Combobox(crow, textvariable=contact_var, state="readonly", width=16)
    contact_combo.pack(side="left", padx=(4, 6))
    contact_combo.bind("<<ComboboxSelected>>", lambda e: on_contact_selected())
    tk.Button(crow, text="＋ Simpan", command=lambda: do_save_contact(),
              bg=PANEL, fg=ACCENT, relief="flat").pack(side="left")
    tk.Button(crow, text="🗑 Hapus", command=lambda: do_delete_contact(),
              bg=PANEL, fg=MUTED, relief="flat").pack(side="left", padx=4)

    irow = tk.Frame(tf, bg=BG); irow.pack(fill="x", padx=8, pady=2)
    tk.Label(irow, text="IP penerima:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side="left")
    tk.Entry(irow, textvariable=ip_var, width=16, bg=PANEL, fg=FG,
             insertbackground=FG, relief="flat").pack(side="left", padx=(4, 10), ipady=2)
    tk.Label(irow, text="Port:", bg=BG, fg=FG, font=("Segoe UI", 9)).pack(side="left")
    tk.Entry(irow, textvariable=port_var, width=7, bg=PANEL, fg=FG,
             insertbackground=FG, relief="flat").pack(side="left", padx=(4, 0), ipady=2)

    brow = tk.Frame(tf, bg=BG); brow.pack(fill="x", padx=8, pady=(2, 8))
    send_btn = tk.Button(brow, text="📤 Kirim .enc…", command=lambda: do_send(),
                         bg=PANEL, fg=ACCENT, relief="flat")
    send_btn.pack(side="left")
    recv_btn = tk.Button(brow, text="📥 Terima file…", command=lambda: do_receive(),
                         bg=PANEL, fg=ACCENT, relief="flat")
    recv_btn.pack(side="left", padx=8)
    tk.Checkbutton(brow, text="🔓 Auto-dekripsi", variable=autodec_var, bg=BG, fg=FG,
                   selectcolor=PANEL, activebackground=BG).pack(side="left", padx=6)

    log = tk.Text(root, height=8, bg="#11111b", fg=FG, relief="flat",
                  font=("Consolas", 9), wrap="word")
    log.pack(fill="both", expand=True, padx=24, pady=(0, 12))
    log.config(state="disabled")

    def write_log(msg, color=FG):
        log.config(state="normal")
        log.tag_config(color, foreground=color)
        log.insert("end", msg + "\n", color)
        log.see("end"); log.config(state="disabled")

    # ---------------- enkripsi/dekripsi handlers ----------------
    def on_mode_change():
        infile_var.set(""); keyfile_var.set(""); pw_entry.delete(0, "end"); refresh()

    def pick_infile():
        if mode_var.get() == "decrypt":
            p = filedialog.askopenfilename(title="Pilih file .enc",
                    filetypes=[("File terenkripsi", "*.enc"), ("Semua file", "*.*")])
        else:
            p = filedialog.askopenfilename(title="Pilih file untuk dienkripsi")
        if p:
            infile_var.set(p); refresh()

    def pick_keyfile():
        p = filedialog.askopenfilename(title="Pilih file kunci (.pem)",
                filetypes=[("Kunci PEM", "*.pem"), ("Semua file", "*.*")])
        if not p:
            return
        keyfile_var.set(p)
        try:
            card = key_fingerprint_card(p, password=pw_entry.get().strip() or None)
            write_log("Fingerprint kunci ini — cocokkan dengan lawan:\n" + card, ACCENT)
        except Exception:
            pass

    def _show_inputs_for(algo_id):
        if algo_id is None:
            for w in (pw_lbl, pw_entry):
                w.grid_remove()
            key_lbl.grid_remove(); kframe.grid_remove()
            keygen_btn.grid_remove(); key_hint.grid_remove()
            return
        is_rsa = algo_id in KEY_ALGOS
        for w in (pw_lbl, pw_entry):
            w.grid() if not is_rsa else w.grid_remove()
        key_lbl.grid() if is_rsa else key_lbl.grid_remove()
        kframe.grid() if is_rsa else kframe.grid_remove()
        keygen_btn.grid() if (is_rsa and mode_var.get() == "encrypt") else keygen_btn.grid_remove()
        if is_rsa:
            key_hint.config(text=("Untuk enkripsi: pilih PUBLIC key (….pub.pem)"
                                  if mode_var.get() == "encrypt"
                                  else "Untuk dekripsi: pilih PRIVATE key (….priv.pem)"))
            key_hint.grid()
        else:
            key_hint.grid_remove()

    def refresh():
        if mode_var.get() == "encrypt":
            algo_combo.config(state="readonly"); algo_lbl.config(fg=FG)
            detect_hint.grid_remove(); _show_inputs_for(ALGORITHMS[algo_var.get()])
            return
        algo_combo.config(state="disabled")
        path = infile_var.get().strip()
        info = peek_algorithm(path) if (path and os.path.isfile(path)) else None
        if info:
            algo_id, name = info
            algo_var.set(name); algo_lbl.config(fg=FG)
            detect_hint.config(text="✓ terbaca otomatis dari file", fg=OK); detect_hint.grid()
            _show_inputs_for(algo_id)
        else:
            algo_lbl.config(fg="#6c7086")
            detect_hint.config(text=("⚠ bukan file .enc CryptoHan" if path else "pilih file .enc dulu →"),
                               fg=(ERR if path else MUTED))
            detect_hint.grid(); _show_inputs_for(None)

    def do_keygen():
        folder = filedialog.askdirectory(title="Simpan kunci di folder…")
        if not folder:
            return
        priv = os.path.join(folder, "cryptohan.priv.pem")
        pub = os.path.join(folder, "cryptohan.pub.pem")
        pw = pw_entry.get().strip() or None
        try:
            generate_rsa_keypair(priv, pub, password=pw)
            card = key_fingerprint_card(pub)
            write_log(f"✓ Kunci dibuat:\n   {priv}\n   {pub}", OK)
            write_log("Fingerprint kunci publik Anda (bacakan ke lawan):\n" + card, ACCENT)
            messagebox.showinfo("Sukses", "Pasangan kunci RSA dibuat.\n\nFingerprint publik:\n" + card)
        except Exception as e:
            write_log(f"✗ Gagal membuat kunci: {e}", ERR)

    def do_fingerprint():
        p = filedialog.askopenfilename(title="Pilih file kunci (.pem)",
                filetypes=[("Kunci PEM", "*.pem"), ("Semua file", "*.*")])
        if not p:
            return
        try:
            card = key_fingerprint_card(p, password=pw_entry.get().strip() or None)
            write_log(f"Fingerprint {os.path.basename(p)}:\n" + card, ACCENT)
            messagebox.showinfo("Fingerprint kunci", card +
                "\n\nBandingkan dengan lawan lewat jalur lain. COCOK = asli, BEDA = MITM.")
        except Exception as e:
            write_log(f"✗ Gagal fingerprint: {e}", ERR)
            messagebox.showerror("Gagal", f"{e}\n\nJika kunci privat terenkripsi, isi Password dulu.")

    def do_run():
        in_path = infile_var.get().strip()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showwarning("Perhatian", "Pilih file input yang valid dulu."); return
        algo_name = algo_var.get(); algo_id = ALGORITHMS[algo_name]
        is_rsa = algo_id in KEY_ALGOS; mode = mode_var.get()
        try:
            if mode == "encrypt":
                out_path = in_path + ".enc"
                if is_rsa:
                    kp = keyfile_var.get().strip()
                    if not kp:
                        messagebox.showwarning("Perhatian", "Pilih PUBLIC key dulu."); return
                    encrypt_file(in_path, out_path, algo_name, public_key=load_public_key(kp))
                else:
                    pw = pw_entry.get()
                    if not pw:
                        messagebox.showwarning("Perhatian", "Isi password dulu."); return
                    encrypt_file(in_path, out_path, algo_name, password=pw)
                write_log(f"✓ Terenkripsi [{algo_name}]\n   → {out_path}", OK)
                messagebox.showinfo("Sukses", f"File berhasil dienkripsi:\n{out_path}")
            else:
                info = peek_algorithm(in_path)
                if info is None:
                    messagebox.showerror("Gagal", "File ini bukan file .enc CryptoHan.")
                    write_log("✗ File bukan format CryptoHan.", ERR); return
                algo_id2, _ = info; is_rsa2 = algo_id2 in KEY_ALGOS
                out_path = _decrypted_out_path(in_path)
                if is_rsa2:
                    kp = keyfile_var.get().strip()
                    if not kp:
                        messagebox.showwarning("Perhatian", "Pilih PRIVATE key dulu."); return
                    priv = load_private_key(kp, password=pw_entry.get().strip() or None)
                    used = decrypt_file(in_path, out_path, private_key=priv)
                else:
                    pw = pw_entry.get()
                    if not pw:
                        messagebox.showwarning("Perhatian", "Isi password dulu."); return
                    used = decrypt_file(in_path, out_path, password=pw)
                write_log(f"✓ Terdekripsi [{used}]\n   → {out_path}", OK)
                messagebox.showinfo("Sukses", f"File berhasil didekripsi:\n{out_path}")
        except Exception as e:
            msg = str(e)
            if "authentication" in msg.lower() or "tag" in msg.lower() or not msg:
                msg = "Password salah, kunci salah, atau file telah diubah."
            write_log(f"✗ Gagal: {msg}", ERR)
            messagebox.showerror("Gagal", msg)

    # ---------------- kontak handlers ----------------
    def refresh_contacts():
        contacts_by_name.clear()
        for c in load_contacts():
            contacts_by_name[c["name"]] = c
        contact_combo["values"] = list(contacts_by_name.keys())

    def on_contact_selected():
        c = contacts_by_name.get(contact_var.get())
        if c:
            ip_var.set(c.get("ip", "")); port_var.set(str(c.get("port", "")))
            if c.get("fingerprint"):
                write_log(f"Kontak '{c['name']}' punya fingerprint tersimpan "
                          f"(akan diverifikasi otomatis).", MUTED)

    def do_save_contact():
        name = simpledialog.askstring("Simpan kontak", "Nama kontak:", parent=root)
        if not name:
            return
        try:
            port = int(port_var.get())
        except ValueError:
            messagebox.showwarning("Perhatian", "Port harus angka."); return
        fp = net.get("last_peer_fp")     # sertakan fingerprint hasil transfer terakhir bila ada
        upsert_contact(name.strip(), ip_var.get().strip(), port, fingerprint=fp)
        refresh_contacts(); contact_var.set(name.strip())
        extra = " (+ fingerprint)" if fp else ""
        write_log(f"Kontak '{name.strip()}' disimpan{extra}.", OK)

    def do_delete_contact():
        name = contact_var.get().strip()
        if not name:
            return
        if messagebox.askyesno("Hapus kontak", f"Hapus kontak '{name}'?"):
            remove_contact(name); refresh_contacts(); contact_var.set("")
            write_log(f"Kontak '{name}' dihapus.", MUTED)

    # ---------------- transfer handlers ----------------
    def make_peer_handler(who, pinned_fp, cname):
        """
        Callback verifikasi fingerprint peer.

        Return
        ------
        True
            Peer dipercaya, transfer boleh dilanjutkan.

        False
            Fingerprint tidak cocok, koneksi HARUS dihentikan.

        None
            Belum ada fingerprint tersimpan (TOFU / first contact).
        """

        def handler(peer_raw):

            fp_full = fp_hex_full(peer_raw)
            net["last_peer_fp"] = fp_full
            card = fingerprint_card(peer_raw)

            # -------------------------------
            # Belum pernah mengenal peer
            # -------------------------------
            if not pinned_fp:
                ui(lambda: write_log(
                    f"Fingerprint {who} belum dikenal.\n"
                    f"Verifikasi melalui jalur luar, kemudian simpan kontak.\n\n"
                    f"{card}",
                    ACCENT
                ))
                return None

            # -------------------------------
            # Fingerprint cocok
            # -------------------------------
            if hmac.compare_digest(pinned_fp, fp_full):
                ui(lambda: write_log(
                    f"✓ {who} berhasil diverifikasi "
                    f"(kontak '{cname}')",
                    OK
                ))
                return True

            # -------------------------------
            # Fingerprint tidak cocok
            # -------------------------------
            ui(lambda: write_log(
                f"✗ FINGERPRINT {who} BERBEDA!\n"
                f"Kontak : {cname}\n"
                f"Transfer dibatalkan.\n"
                f"Kemungkinan terjadi Man-in-the-Middle Attack.",
                ERR
            ))

            return False

        return handler

    def do_send():
        if not _HAS_NOISE:
            messagebox.showerror("Butuh library",
                "Fitur kirim butuh 'noiseprotocol'.\n\npip install noiseprotocol"); return
        host = ip_var.get().strip() or "127.0.0.1"
        try:
            port = int(port_var.get())
        except ValueError:
            messagebox.showwarning("Perhatian", "Port harus angka."); return
        fp = filedialog.askopenfilename(title="Pilih file .enc untuk dikirim",
                filetypes=[("File terenkripsi", "*.enc"), ("Semua file", "*.*")])
        if not fp:
            return
        cname = contact_var.get().strip()
        pinned = (contacts_by_name.get(cname) or {}).get("fingerprint")
        priv_path, _ = ensure_transport_identity()
        mypriv = load_transport_private_raw(priv_path)
        handler = make_peer_handler("PENERIMA", pinned, cname)

        def worker():
            try:
                ui(lambda: write_log(f"Menghubungi {host}:{port}…", ACCENT))
                peer, nbytes = send_file(host, port, fp, mypriv, on_peer=handler)
                ui(lambda: write_log(f"✓ Terkirim {nbytes} byte ke {host}:{port}", OK))
                ui(lambda: messagebox.showinfo("Terkirim",
                    f"File terkirim ({nbytes} byte).\nCek log untuk verifikasi fingerprint."))
            except Exception as e:
                ui(lambda: write_log(f"✗ Gagal kirim: {e}", ERR))
                ui(lambda: messagebox.showerror("Gagal kirim", str(e)))
        threading.Thread(target=worker, daemon=True).start()

    def do_receive():
        if not _HAS_NOISE:
            messagebox.showerror("Butuh library",
                "Fitur terima butuh 'noiseprotocol'.\n\npip install noiseprotocol"); return
        if net["receiving"]:
            net["stop"][0] = True
            return
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
        my_fp = fingerprint_card(transport_public_raw_from_private(mypriv))
        net["stop"][0] = False; net["receiving"] = True
        recv_btn.config(text="■ Berhenti")
        write_log(f"Menunggu koneksi di port {port}…\n"
                  f"Fingerprint transport Anda (untuk pengirim):\n{my_fp}", ACCENT)
        handler = make_peer_handler("PENGIRIM", pinned, cname)

        def worker():
            try:
                peer, out_path = receive_file(port, outdir, mypriv,
                        on_peer=handler, stop_flag=net["stop"])
                if out_path is None:
                    ui(lambda: write_log("Menunggu dibatalkan.", MUTED))
                else:
                    ui(lambda: after_receive(out_path))
            except Exception as e:
                ui(lambda: write_log(f"✗ Gagal terima: {e}", ERR))
            finally:
                net["receiving"] = False
                ui(lambda: recv_btn.config(text="📥 Terima file…"))
        threading.Thread(target=worker, daemon=True).start()

    def after_receive(enc_path):
        """Dijalankan di main thread: simpan + (opsional) auto-dekripsi."""
        write_log(f"✓ File diterima → {enc_path}", OK)
        if not autodec_var.get():
            messagebox.showinfo("File diterima",
                f"Tersimpan:\n{enc_path}\n\n(Auto-dekripsi mati — dekripsi manual.)")
            return
        info = peek_algorithm(enc_path)
        if info is None:
            messagebox.showinfo("File diterima", f"Tersimpan (bukan .enc CryptoHan):\n{enc_path}")
            return
        algo_id, name = info
        try:
            if algo_id in KEY_ALGOS:
                kp = keyfile_var.get().strip()
                if not kp:
                    kp = filedialog.askopenfilename(
                        title="File RSA-Hybrid diterima — pilih PRIVATE key untuk dekripsi",
                        filetypes=[("Kunci PEM", "*.pem"), ("Semua file", "*.*")])
                    if not kp:
                        write_log("Auto-dekripsi dilewati (tidak ada kunci privat).", MUTED)
                        return
                priv = load_private_key(kp, password=pw_entry.get().strip() or None)
                dname, out = auto_decrypt(enc_path, private_key=priv)
            else:
                pw = pw_entry.get()
                if not pw:
                    pw = simpledialog.askstring("Password",
                            f"File {name} diterima. Masukkan password untuk dekripsi:",
                            show="•", parent=root)
                    if not pw:
                        write_log("Auto-dekripsi dilewati (tidak ada password).", MUTED)
                        return
                dname, out = auto_decrypt(enc_path, password=pw)
            write_log(f"✓ Auto-dekripsi [{dname}]\n   → {out}", OK)
            messagebox.showinfo("Auto-dekripsi sukses",
                f"File diterima & didekripsi otomatis:\n{out}")
        except Exception as e:
            write_log(f"✗ Auto-dekripsi gagal: {e}", ERR)
            messagebox.showerror("Auto-dekripsi gagal",
                f"{e}\n\nFile .enc tetap tersimpan:\n{enc_path}")

    def on_close():
        net["stop"][0] = True
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    refresh(); refresh_contacts()
    write_log("Siap. Kirim file .enc ke IP penerima; penerima auto-dekripsi.", ACCENT)
    if not _HAS_NOISE:
        write_log("Fitur 'Kirim langsung' nonaktif — pasang: pip install noiseprotocol", MUTED)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
