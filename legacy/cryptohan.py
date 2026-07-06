#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoHan - Aplikasi Enkripsi & Dekripsi File + Verifikasi Fingerprint
========================================================================
Aplikasi desktop (Tkinter) untuk mengenkripsi dan mendekripsi file apa pun
dengan 2 algoritma yang bisa dipilih:

    1. AES-256-GCM          (simetris, berbasis password)   -- rekomendasi utama
    5. RSA-2048 Hybrid      (asimetris, berbasis kunci)     -- pakai public/private key

Ditambah fitur VERIFIKASI FINGERPRINT (anti-MITM):
- Fingerprint = SHA-256 dari kunci publik, ditampilkan sebagai kata / hex / angka.
- Dipakai untuk memastikan kunci publik yang diterima BENAR milik lawan bicara
  (dibandingkan lewat jalur luar: telepon / tatap layar), menutup celah
  man-in-the-middle saat pertukaran kunci pada mode RSA-Hybrid.

Catatan kriptografer:
- RSA murni hanya bisa mengenkripsi data kecil. Untuk file besar dipakai
  "hybrid encryption": file dikunci AES, kunci AES-nya dibungkus RSA-OAEP.
- Password diubah jadi kunci lewat PBKDF2-HMAC-SHA256 (600.000 iterasi + salt).

Format file terenkripsi (.enc):
    [4 byte magic 'FCH1'][1 byte algo_id][payload spesifik algoritma]

Dependensi: pip install cryptography
"""

import os
import struct
import secrets
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

# ---------------------------------------------------------------------------
# KONSTANTA & FORMAT
# ---------------------------------------------------------------------------
MAGIC = b"FCH1"            # penanda file CryptoHan versi 1
PBKDF2_ITERS = 600_000     # iterasi derivasi kunci dari password Sesuai rekomendasi owasp
SALT_LEN = 16              # panjang salt untuk PBKDF2 (16B = 128 bit) Sesuaikan NIST SP 800-132

ALGORITHMS = {
    "AES-256-GCM":          1,
    "RSA-2048 Hybrid":      5,
}
ALGO_BY_ID = {v: k for k, v in ALGORITHMS.items()}

PASSWORD_ALGOS = {1}       # algoritma yang memakai password (simetris)
KEY_ALGOS = {5}            # algoritma yang memakai file kunci (asimetris)


# ---------------------------------------------------------------------------
# UTILITAS KUNCI (PBKDF2)
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes, length: int) -> bytes:
    """Turunkan kunci sepanjang `length` byte dari password memakai PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# ENKRIPSI PER ALGORITMA  ->  mengembalikan payload (tanpa magic+algo_id)
# ---------------------------------------------------------------------------
def _enc_aes_gcm(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(12)                    # AES-GCM nonce = 96 bit
    key = derive_key(password, salt, 32)               # AES-256 = 32 byte
    ct = AESGCM(key).encrypt(nonce, data, None)        # ciphertext + tag (16B)
    return salt + nonce + ct


def _enc_rsa_hybrid(data: bytes, public_key) -> bytes:
    aes_key = secrets.token_bytes(32)                  # kunci AES acak sekali pakai
    nonce = secrets.token_bytes(12)
    ct = AESGCM(aes_key).encrypt(nonce, data, None)    # file dikunci AES
    enc_key = public_key.encrypt(                       # kunci AES dibungkus RSA-OAEP
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return struct.pack(">H", len(enc_key)) + enc_key + nonce + ct


# ---------------------------------------------------------------------------
# DEKRIPSI PER ALGORITMA  <-  menerima payload (tanpa magic+algo_id)
# ---------------------------------------------------------------------------
def _dec_aes_gcm(payload: bytes, password: str) -> bytes:
    salt, nonce, ct = payload[:16], payload[16:28], payload[28:]
    key = derive_key(password, salt, 32)
    return AESGCM(key).decrypt(nonce, ct, None)


def _dec_rsa_hybrid(payload: bytes, private_key) -> bytes:
    (klen,) = struct.unpack(">H", payload[:2])
    enc_key = payload[2:2 + klen]
    rest = payload[2 + klen:]
    nonce, ct = rest[:12], rest[12:]
    aes_key = private_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AESGCM(aes_key).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# API TINGKAT FILE
# ---------------------------------------------------------------------------
def encrypt_file(in_path: str, out_path: str, algo_name: str,
                 password: str = None, public_key=None) -> None:
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


def decrypt_file(in_path: str, out_path: str,
                 password: str = None, private_key=None) -> str:
    with open(in_path, "rb") as f:
        blob = f.read()

    if blob[:4] != MAGIC:
        raise ValueError("File bukan hasil enkripsi CryptoHan (header tidak cocok).")
    algo_id = blob[4]
    payload = blob[5:]
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


def peek_algorithm(path: str):
    """Baca header file .enc dan kembalikan (algo_id, nama) tanpa mendekripsi."""
    try:
        with open(path, "rb") as f:
            head = f.read(5)
    except OSError:
        return None
    if len(head) < 5 or head[:4] != MAGIC:
        return None
    algo_id = head[4]
    name = ALGO_BY_ID.get(algo_id)
    if name is None:
        return None
    return algo_id, name


# ---------------------------------------------------------------------------
# UTILITAS KUNCI RSA
# ---------------------------------------------------------------------------
def generate_rsa_keypair(priv_path: str, pub_path: str, password: str = None) -> None:
    """Buat sepasang kunci RSA-2048 dan simpan ke file PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())

    with open(priv_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        ))
    with open(pub_path, "wb") as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path: str, password: str = None):
    with open(path, "rb") as f:
        pw = password.encode() if password else None
        return serialization.load_pem_private_key(f.read(), password=pw)


# ===========================================================================
#  FINGERPRINT (verifikasi identitas anti-MITM)
# ===========================================================================
# 256 kata (satu kata per nilai byte) untuk fingerprint yang mudah diucapkan.
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


def _canonical_public_bytes(path: str, password: str = None) -> bytes:
    """Ambil byte kanonik (DER SubjectPublicKeyInfo) dari sebuah file .pem.
    Menerima file kunci PUBLIK; bila diberi kunci PRIVAT, turunkan publiknya."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        pub = serialization.load_pem_public_key(data)
    except Exception:
        pw = password.encode() if password else None
        pub = serialization.load_pem_private_key(data, password=pw).public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fingerprint_digest(pub_bytes: bytes) -> bytes:
    """SHA-256 penuh (32 byte) dari kunci publik. Basis semua format."""
    return hashlib.sha256(pub_bytes).digest()


def fp_words(pub_bytes: bytes, nwords: int = 8) -> str:
    """8 kata (64 bit) untuk dibaca keras / lewat telepon."""
    d = fingerprint_digest(pub_bytes)
    return " ".join(WORDS[b] for b in d[:nwords])


def fp_hex(pub_bytes: bytes, nbytes: int = 16, group: int = 2) -> str:
    """Hex berkelompok, 16 byte (128 bit), untuk banding di layar."""
    d = fingerprint_digest(pub_bytes)[:nbytes]
    h = d.hex().upper()
    return " ".join(h[i:i + group * 2] for i in range(0, len(h), group * 2))


def fp_numeric(pub_bytes: bytes, nbytes: int = 8, group: int = 5) -> str:
    """Deretan angka gaya 'safety number' (universal lintas bahasa)."""
    d = fingerprint_digest(pub_bytes)[:nbytes]
    digits = str(int.from_bytes(d, "big")).zfill(nbytes * 3)
    return " ".join(digits[i:i + group] for i in range(0, len(digits), group))


def fingerprint_card(pub_bytes: bytes) -> str:
    """Ketiga format sekaligus untuk ditampilkan ke pengguna."""
    return (f"  Kata    : {fp_words(pub_bytes)}\n"
            f"  Hex     : {fp_hex(pub_bytes)}\n"
            f"  Numerik : {fp_numeric(pub_bytes)}")


def key_fingerprint_card(path: str, password: str = None) -> str:
    """Fingerprint dari sebuah file kunci .pem (publik atau privat)."""
    return fingerprint_card(_canonical_public_bytes(path, password))


def verify_match(pub_bytes_a: bytes, pub_bytes_b: bytes) -> bool:
    """Bandingkan dua fingerprint SHA-256 penuh secara constant-time."""
    return hmac.compare_digest(fingerprint_digest(pub_bytes_a),
                               fingerprint_digest(pub_bytes_b))


# ===========================================================================
#  ANTARMUKA GRAFIS (Tkinter)
# ===========================================================================
def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    BG = "#1e1e2e"; FG = "#cdd6f4"; ACCENT = "#89b4fa"
    PANEL = "#313244"; OK = "#a6e3a1"; ERR = "#f38ba8"

    root = tk.Tk()
    root.title("CryptoHan — Enkripsi, Dekripsi & Verifikasi")
    root.geometry("640x620")
    root.configure(bg=BG)
    root.resizable(False, False)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("TCombobox", fieldbackground=PANEL, background=PANEL)

    # --- state ---
    mode_var = tk.StringVar(value="encrypt")
    algo_var = tk.StringVar(value="AES-256-GCM")
    infile_var = tk.StringVar()
    keyfile_var = tk.StringVar()
    show_pw = tk.BooleanVar(value=False)

    def lbl(parent, text, **kw):
        return tk.Label(parent, text=text, bg=BG, fg=FG, font=("Segoe UI", 10), **kw)

    # --- header ---
    tk.Label(root, text="🔐  CryptoHan", bg=BG, fg=ACCENT,
             font=("Segoe UI", 18, "bold")).pack(pady=(16, 0))
    tk.Label(root, text="Enkripsi, dekripsi & verifikasi fingerprint",
             bg=BG, fg="#9399b2", font=("Segoe UI", 9)).pack(pady=(0, 12))

    body = tk.Frame(root, bg=BG); body.pack(fill="both", expand=True, padx=24)

    # --- mode ---
    lbl(body, "Mode:").grid(row=0, column=0, sticky="w", pady=6)
    mframe = tk.Frame(body, bg=BG); mframe.grid(row=0, column=1, sticky="w")
    tk.Radiobutton(mframe, text="Enkripsi", variable=mode_var, value="encrypt",
                   bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG,
                   command=lambda: on_mode_change()).pack(side="left", padx=(0, 12))
    tk.Radiobutton(mframe, text="Dekripsi", variable=mode_var, value="decrypt",
                   bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG,
                   command=lambda: on_mode_change()).pack(side="left")

    # --- algoritma ---
    algo_lbl = lbl(body, "Algoritma:")
    algo_lbl.grid(row=1, column=0, sticky="w", pady=6)
    algo_combo = ttk.Combobox(body, textvariable=algo_var, state="readonly",
                              values=list(ALGORITHMS.keys()), width=28)
    algo_combo.grid(row=1, column=1, sticky="w")
    algo_combo.bind("<<ComboboxSelected>>", lambda e: refresh())
    detect_hint = tk.Label(body, text="", bg=BG, fg=ACCENT,
                           font=("Segoe UI", 8), wraplength=220, justify="left")
    detect_hint.grid(row=1, column=2, sticky="w", padx=4)

    # --- file input ---
    lbl(body, "File:").grid(row=2, column=0, sticky="w", pady=6)
    fframe = tk.Frame(body, bg=BG); fframe.grid(row=2, column=1, sticky="w")
    tk.Entry(fframe, textvariable=infile_var, width=30, bg=PANEL, fg=FG,
             insertbackground=FG, relief="flat").pack(side="left", ipady=3)
    tk.Button(fframe, text="Pilih…", command=lambda: pick_infile(),
              bg=PANEL, fg=FG, relief="flat").pack(side="left", padx=6)

    # --- password ---
    pw_lbl = lbl(body, "Password:")
    pw_lbl.grid(row=3, column=0, sticky="w", pady=6)
    pw_entry = tk.Entry(body, width=30, show="•", bg=PANEL, fg=FG,
                        insertbackground=FG, relief="flat")
    pw_entry.grid(row=3, column=1, sticky="w", ipady=3)
    tk.Checkbutton(body, text="Tampilkan", variable=show_pw, bg=BG, fg="#9399b2",
                   selectcolor=PANEL, activebackground=BG,
                   command=lambda: pw_entry.config(show="" if show_pw.get() else "•")
                   ).grid(row=3, column=2, sticky="w", padx=4)

    # --- key file (RSA) ---
    key_lbl = lbl(body, "File kunci:")
    key_lbl.grid(row=4, column=0, sticky="w", pady=6)
    kframe = tk.Frame(body, bg=BG); kframe.grid(row=4, column=1, sticky="w")
    tk.Entry(kframe, textvariable=keyfile_var, width=30, bg=PANEL, fg=FG,
             insertbackground=FG, relief="flat").pack(side="left", ipady=3)
    tk.Button(kframe, text="Pilih…", command=lambda: pick_keyfile(),
              bg=PANEL, fg=FG, relief="flat").pack(side="left", padx=6)
    key_hint = tk.Label(body, text="", bg=BG, fg="#9399b2", font=("Segoe UI", 8))
    key_hint.grid(row=5, column=1, sticky="w")

    # --- RSA keygen ---
    keygen_btn = tk.Button(body, text="🔑 Buat Pasangan Kunci RSA",
                           command=lambda: do_keygen(), bg=PANEL, fg=ACCENT, relief="flat")
    keygen_btn.grid(row=6, column=1, sticky="w", pady=(2, 4))

    # --- Fingerprint (selalu tersedia) ---
    fp_btn = tk.Button(body, text="🔎 Fingerprint / Verifikasi Kunci…",
                       command=lambda: do_fingerprint(), bg=PANEL, fg=ACCENT, relief="flat")
    fp_btn.grid(row=7, column=1, sticky="w", pady=(2, 8))

    # --- run button ---
    run_btn = tk.Button(root, text="JALANKAN", command=lambda: do_run(),
                        bg=ACCENT, fg=BG, font=("Segoe UI", 11, "bold"),
                        relief="flat", padx=20, pady=8)
    run_btn.pack(pady=8)

    # --- log ---
    log = tk.Text(root, height=8, bg="#11111b", fg=FG, relief="flat",
                  font=("Consolas", 9), wrap="word")
    log.pack(fill="x", padx=24, pady=(0, 16))
    log.config(state="disabled")

    def write_log(msg, color=FG):
        log.config(state="normal")
        log.tag_config(color, foreground=color)
        log.insert("end", msg + "\n", color)
        log.see("end")
        log.config(state="disabled")

    # --- handlers ---
    def on_mode_change():
        infile_var.set(""); keyfile_var.set("")
        pw_entry.delete(0, "end")
        refresh()

    def pick_infile():
        if mode_var.get() == "decrypt":
            p = filedialog.askopenfilename(title="Pilih file .enc",
                    filetypes=[("File terenkripsi", "*.enc"), ("Semua file", "*.*")])
        else:
            p = filedialog.askopenfilename(title="Pilih file untuk dienkripsi")
        if p:
            infile_var.set(p)
            refresh()

    def pick_keyfile():
        p = filedialog.askopenfilename(title="Pilih file kunci (.pem)",
                filetypes=[("Kunci PEM", "*.pem"), ("Semua file", "*.*")])
        if not p:
            return
        keyfile_var.set(p)
        # Saat memilih kunci publik lawan untuk enkripsi, tampilkan fingerprint-nya
        # supaya bisa diverifikasi dulu sebelum mengenkripsi (anti-MITM).
        try:
            card = key_fingerprint_card(p, password=pw_entry.get().strip() or None)
            write_log("Fingerprint kunci ini — cocokkan dengan lawan bicara:\n" + card, ACCENT)
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
        if is_rsa and mode_var.get() == "encrypt":
            keygen_btn.grid()
        else:
            keygen_btn.grid_remove()
        if is_rsa:
            if mode_var.get() == "encrypt":
                key_hint.config(text="Untuk enkripsi: pilih PUBLIC key (….pub.pem)")
            else:
                key_hint.config(text="Untuk dekripsi: pilih PRIVATE key (….priv.pem)")
            key_hint.grid()
        else:
            key_hint.grid_remove()

    def refresh():
        mode = mode_var.get()
        if mode == "encrypt":
            algo_combo.config(state="readonly")
            algo_lbl.config(fg=FG)
            detect_hint.grid_remove()
            _show_inputs_for(ALGORITHMS[algo_var.get()])
            return
        # ---- mode dekripsi: algoritma dibaca otomatis dari file ----
        algo_combo.config(state="disabled")
        path = infile_var.get().strip()
        info = peek_algorithm(path) if (path and os.path.isfile(path)) else None
        if info:
            algo_id, name = info
            algo_var.set(name)
            algo_lbl.config(fg=FG)
            detect_hint.config(text="✓ terbaca otomatis dari file", fg=OK)
            detect_hint.grid()
            _show_inputs_for(algo_id)
        else:
            algo_lbl.config(fg="#6c7086")
            if path:
                detect_hint.config(text="⚠ bukan file .enc CryptoHan", fg=ERR)
            else:
                detect_hint.config(text="pilih file .enc dulu →", fg="#9399b2")
            detect_hint.grid()
            _show_inputs_for(None)

    def do_keygen():
        folder = filedialog.askdirectory(title="Simpan kunci di folder…")
        if not folder:
            return
        name = "cryptohan"
        priv = os.path.join(folder, f"{name}.priv.pem")
        pub = os.path.join(folder, f"{name}.pub.pem")
        pw = pw_entry.get().strip() or None
        try:
            generate_rsa_keypair(priv, pub, password=pw)
            card = key_fingerprint_card(pub)
            write_log(f"✓ Kunci dibuat:\n   private: {priv}\n   public : {pub}", OK)
            write_log("Fingerprint kunci publik Anda (bacakan ke lawan):\n" + card, ACCENT)
            messagebox.showinfo("Sukses",
                "Pasangan kunci RSA berhasil dibuat.\n\n"
                "• .pub.pem  → untuk ENKRIPSI (boleh dibagikan)\n"
                "• .priv.pem → untuk DEKRIPSI (RAHASIA!)\n\n"
                "Fingerprint kunci publik Anda:\n" + card +
                "\n\nBacakan fingerprint ini ke lawan lewat telepon/tatap muka\n"
                "agar mereka yakin kunci yang mereka terima benar milik Anda.")
        except Exception as e:
            write_log(f"✗ Gagal membuat kunci: {e}", ERR)

    def do_fingerprint():
        p = filedialog.askopenfilename(
            title="Pilih file kunci (.pem) untuk difingerprint",
            filetypes=[("Kunci PEM", "*.pem"), ("Semua file", "*.*")])
        if not p:
            return
        try:
            card = key_fingerprint_card(p, password=pw_entry.get().strip() or None)
            write_log(f"Fingerprint {os.path.basename(p)}:\n" + card, ACCENT)
            messagebox.showinfo("Fingerprint kunci",
                f"Fingerprint dari:\n{p}\n\n" + card +
                "\n\nBandingkan nilai ini dengan lawan bicara lewat jalur lain\n"
                "(telepon / tatap layar). Jika COCOK, kunci asli — tidak ada MITM.\n"
                "Jika BERBEDA, jangan dipakai — ada kemungkinan penyusup.")
        except Exception as e:
            write_log(f"✗ Gagal fingerprint: {e}", ERR)
            messagebox.showerror("Gagal",
                f"Tidak bisa membaca kunci.\n{e}\n\n"
                "Jika kunci privat terenkripsi, isi passwordnya di kolom Password dulu.")

    def do_run():
        in_path = infile_var.get().strip()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showwarning("Perhatian", "Pilih file input yang valid dulu.")
            return
        algo_name = algo_var.get()
        algo_id = ALGORITHMS[algo_name]
        is_rsa = algo_id in KEY_ALGOS
        mode = mode_var.get()

        try:
            if mode == "encrypt":
                out_path = in_path + ".enc"
                if is_rsa:
                    kp = keyfile_var.get().strip()
                    if not kp:
                        messagebox.showwarning("Perhatian", "Pilih PUBLIC key dulu.")
                        return
                    pub = load_public_key(kp)
                    encrypt_file(in_path, out_path, algo_name, public_key=pub)
                else:
                    pw = pw_entry.get()
                    if not pw:
                        messagebox.showwarning("Perhatian", "Isi password dulu.")
                        return
                    encrypt_file(in_path, out_path, algo_name, password=pw)
                write_log(f"✓ Terenkripsi [{algo_name}]\n   → {out_path}", OK)
                messagebox.showinfo("Sukses", f"File berhasil dienkripsi:\n{out_path}")

            else:  # decrypt — algoritma ditentukan oleh ISI FILE, bukan dropdown
                info = peek_algorithm(in_path)
                if info is None:
                    messagebox.showerror("Gagal",
                        "File ini bukan file .enc CryptoHan yang valid.")
                    write_log("✗ File bukan format CryptoHan.", ERR)
                    return
                algo_id, algo_name = info
                is_rsa = algo_id in KEY_ALGOS

                base = in_path[:-4] if in_path.endswith(".enc") else in_path + ".dec"
                out_path = base
                if os.path.exists(out_path):
                    root_, ext = os.path.splitext(base)
                    out_path = f"{root_}_decrypted{ext}"
                if is_rsa:
                    kp = keyfile_var.get().strip()
                    if not kp:
                        messagebox.showwarning("Perhatian", "Pilih PRIVATE key dulu.")
                        return
                    pw = pw_entry.get().strip() or None
                    priv = load_private_key(kp, password=pw)
                    used = decrypt_file(in_path, out_path, private_key=priv)
                else:
                    pw = pw_entry.get()
                    if not pw:
                        messagebox.showwarning("Perhatian", "Isi password dulu.")
                        return
                    used = decrypt_file(in_path, out_path, password=pw)
                write_log(f"✓ Terdekripsi [{used}]\n   → {out_path}", OK)
                messagebox.showinfo("Sukses", f"File berhasil didekripsi:\n{out_path}")

        except Exception as e:
            msg = str(e)
            if "authentication" in msg.lower() or "tag" in msg.lower() or not msg:
                msg = "Password salah, kunci salah, atau file telah diubah."
            write_log(f"✗ Gagal: {msg}", ERR)
            messagebox.showerror("Gagal", msg)

    refresh()
    write_log("Siap. Pilih mode, algoritma, dan file lalu klik JALANKAN.", ACCENT)
    write_log("Tip: pakai '🔎 Fingerprint' untuk memverifikasi kunci publik lawan "
              "sebelum mengenkripsi (anti-MITM).", "#9399b2")
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
