"""Antarmuka grafis (Tkinter)."""

import os
import hmac
import threading

from .config import APP_NAME, APP_VERSION, ALGO_NAMES, NAME_TO_ALGO, ALGO_RSA, DEFAULT_PORT, IDENTITY_DIR
from .logging_setup import get_logger
from .crypto import (
    peek_algorithm, encrypt_stream, decrypt_stream, decrypted_out_path, auto_decrypt,
)
from .keys import (
    generate_rsa_keypair, load_public_key, load_private_key, ensure_transport_identity,
    load_transport_private_raw, transport_public_raw_from_private,
    get_default_privkey, set_default_privkey,
)
from .fingerprint import fp_card, fp_key_card, fp_hex_full
from .contacts import load_contacts, upsert_contact, remove_contact
from .transport import HAS_NOISE, send_file, Receiver


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
    default_privkey = get_default_privkey()
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
        infile_var.set(""); pw_entry.delete(0, "end")
        keyfile_var.set(get_default_privkey() or "" if mode_var.get() == "decrypt" else "")
        refresh()

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
        if mode_var.get() == "decrypt":
            set_default_privkey(p)
            write_log(f"Kunci privat ini dijadikan default (dipakai otomatis saat auto-dekripsi berikutnya): {p}", MUTED)
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
                err = str(e)
                ui(lambda: write_log(f"✗ Gagal kirim: {err}", ERR, "error"))
                ui(lambda: messagebox.showerror("Gagal kirim", err))
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
                kp = keyfile_var.get().strip() or get_default_privkey() or ""
                if not kp:
                    kp = filedialog.askopenfilename(
                        title="RSA-Hybrid diterima — pilih PRIVATE key untuk dekripsi",
                        filetypes=[("Kunci PEM", "*.pem"), ("Semua", "*.*")])
                    if not kp:
                        write_log("Auto-dekripsi dilewati (tanpa kunci privat).", MUTED); return
                    set_default_privkey(kp)
                    write_log(f"Kunci privat ini dijadikan default untuk auto-dekripsi berikutnya: {kp}", MUTED)
                priv = load_private_key(kp, password=pw_entry.get().strip() or None)
                dn, out = auto_decrypt(enc_path, private_key=priv, progress=set_progress)
            else:
                pw = pw_entry.get() or simpledialog.askstring(
                    "Password", f"File {name} diterima. Password untuk dekripsi:", show="•", parent=root)
                if not pw:
                    write_log("Auto-dekripsi dilewati (tanpa password).", MUTED); return
                dn, out = auto_decrypt(enc_path, password=pw, progress=set_progress)
            write_log(f"✓ Auto-dekripsi [{dn}] → {out}", OK)
            try:
                os.remove(enc_path)
                write_log(f"🗑 File .enc dihapus (hanya hasil dekripsi yang disimpan): {enc_path}", MUTED)
            except OSError as e:
                write_log(f"⚠ Gagal menghapus .enc ({enc_path}): {e}", ERR, "warning")
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
    if default_privkey:
        write_log(f"Kunci privat default (dipakai otomatis saat auto-dekripsi): {default_privkey}", MUTED)
    if not HAS_NOISE:
        write_log("Fitur transfer nonaktif — pasang: pip install noiseprotocol", MUTED, "warning")
    log.info("Aplikasi dijalankan.")
    root.mainloop()
