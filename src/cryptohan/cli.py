"""Antarmuka command-line (CLI) — dispatcher headless yang memakai fungsi
inti yang sama dengan GUI (`cryptohan.gui`), tanpa duplikasi logika."""

import argparse
import getpass
import sys

from .config import ALGO_AES, ALGO_RSA, DEFAULT_PORT, CryptoError, TransportError, FingerprintMismatchError
from .crypto import encrypt_stream, decrypt_stream, peek_algorithm, decrypted_out_path, auto_decrypt
from .keys import (
    generate_rsa_keypair, generate_transport_identity, load_public_key, load_private_key,
    ensure_transport_identity, load_transport_private_raw,
)
from .fingerprint import fp_key_card
from .contacts import load_contacts, upsert_contact, remove_contact


def _resolve_password(args, prompt="Password: "):
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    if getattr(args, "password", None):
        return args.password
    return getpass.getpass(prompt)


def _progress_printer(label):
    def cb(done, total):
        pct = int(done * 100 / total) if total else 100
        print(f"\r{label}: {pct}% ({done}/{total} bytes)", end="", flush=True)
        if done >= total:
            print()
    return cb


def _cmd_encrypt(args):
    out_path = args.out or (args.infile + ".enc")
    if args.algo == "rsa":
        pub = load_public_key(args.pubkey)
        encrypt_stream(args.infile, out_path, ALGO_RSA, public_key=pub,
                       progress=_progress_printer("encrypt"))
    else:
        password = _resolve_password(args, "Password enkripsi: ")
        encrypt_stream(args.infile, out_path, ALGO_AES, password=password,
                       progress=_progress_printer("encrypt"))
    print(f"OK: {out_path}")
    return 0


def _cmd_decrypt(args):
    info = peek_algorithm(args.encfile)
    if info is None:
        print("Error: bukan file .enc CryptoHan.", file=sys.stderr)
        return 1
    algo_id, name = info
    out_path = args.out or decrypted_out_path(args.encfile)
    if algo_id == ALGO_RSA:
        priv = load_private_key(args.privkey, password=args.keypassword)
        decrypt_stream(args.encfile, out_path, private_key=priv,
                       progress=_progress_printer("decrypt"))
    else:
        password = _resolve_password(args, "Password dekripsi: ")
        decrypt_stream(args.encfile, out_path, password=password,
                       progress=_progress_printer("decrypt"))
    print(f"\nOK [{name}]: {out_path}")
    return 0


def _cmd_keygen(args):
    password = args.password or None
    if args.kind == "rsa":
        generate_rsa_keypair(args.priv, args.pub, password=password)
    else:
        generate_transport_identity(args.priv, args.pub, password=password)
    print(f"OK: {args.priv}\n    {args.pub}")
    print(fp_key_card(args.pub))
    return 0


def _cmd_fingerprint(args):
    password = args.password or None
    print(fp_key_card(args.keyfile, password=password))
    return 0


def _cmd_send(args):
    from .transport import send_file, HAS_NOISE
    if not HAS_NOISE:
        print("Error: library 'noiseprotocol' belum terpasang.", file=sys.stderr)
        return 1
    host, port, expected_fp = args.host, args.port, args.expect_fingerprint
    if args.contact:
        contacts, _ = load_contacts()
        c = next((c for c in contacts if c.get("name") == args.contact), None)
        if c is None:
            print(f"Error: kontak '{args.contact}' tidak ditemukan.", file=sys.stderr)
            return 1
        host = host or c.get("ip")
        port = port or c.get("port")
        expected_fp = expected_fp or c.get("fingerprint")
    if not host or not port:
        print("Error: --host/--port (atau --contact) diperlukan.", file=sys.stderr)
        return 1

    priv_path, _ = ensure_transport_identity()
    static_priv_raw = load_transport_private_raw(priv_path)

    def on_peer(peer_raw):
        from .fingerprint import fp_hex_full
        print(f"Fingerprint penerima: {fp_hex_full(peer_raw)}")

    peer_fp, size, ack = send_file(host, port, args.encfile, static_priv_raw,
                                   expected_fp=expected_fp, on_peer=on_peer,
                                   progress=_progress_printer("send"))
    print(f"OK: terkirim {size} byte, ack={ack}")
    return 0 if ack == "OK" else 1


def _cmd_receive(args):
    from .transport import Receiver, HAS_NOISE
    if not HAS_NOISE:
        print("Error: library 'noiseprotocol' belum terpasang.", file=sys.stderr)
        return 1
    expected_fp = args.expect_fingerprint
    if args.contact:
        contacts, _ = load_contacts()
        c = next((c for c in contacts if c.get("name") == args.contact), None)
        expected_fp = expected_fp or (c.get("fingerprint") if c else None)

    priv_path, _ = ensure_transport_identity()
    static_priv_raw = load_transport_private_raw(priv_path)

    state = {"code": 0}

    def on_result(status, info):
        if status == "received":
            print(f"\nOK: file diterima -> {info}")
            if args.auto_decrypt:
                try:
                    if args.privkey:
                        priv = load_private_key(args.privkey, password=args.keypassword)
                        dn, out = auto_decrypt(info, private_key=priv)
                    else:
                        dn, out = auto_decrypt(info, password=args.password)
                    print(f"OK: auto-dekripsi [{dn}] -> {out}")
                except Exception as e:
                    print(f"Error: auto-dekripsi gagal: {e}", file=sys.stderr)
                    state["code"] = 1
        else:
            print(f"\n{status}: {info}", file=sys.stderr)
            # mitm = penolakan keamanan (fingerprint tak cocok) -> kode khusus
            # supaya skrip/monitoring pemanggil bisa membedakannya dari error biasa.
            state["code"] = 2 if status == "mitm" else 1

    def on_peer(peer_raw):
        from .fingerprint import fp_hex_full
        print(f"Fingerprint pengirim: {fp_hex_full(peer_raw)}")

    rcv = Receiver(args.port, args.out_dir, static_priv_raw, expected_fp=expected_fp,
                  on_peer=on_peer, on_progress=_progress_printer("receive"),
                  on_result=on_result)
    print(f"Menunggu koneksi di port {args.port}… (Ctrl+C untuk berhenti)")
    try:
        rcv.serve_forever()
    except KeyboardInterrupt:
        rcv.stop()
        print("\nDihentikan.")
    return state["code"]


def _cmd_contacts(args):
    if args.contacts_command == "add":
        upsert_contact(args.name, args.ip, args.port, fingerprint=args.fingerprint)
        print(f"OK: kontak '{args.name}' disimpan.")
        return 0
    if args.contacts_command == "remove":
        remove_contact(args.name)
        print(f"OK: kontak '{args.name}' dihapus.")
        return 0
    # list
    contacts, ok = load_contacts()
    if not ok:
        print("Peringatan: contacts.json gagal verifikasi integritas (HMAC).", file=sys.stderr)
    for c in contacts:
        fp = c.get("fingerprint", "-")
        print(f"{c['name']:<20} {c['ip']}:{c['port']}  fingerprint={fp}")
    return 0


def _cmd_gui(_args):
    from .gui import launch_gui
    launch_gui()
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="cryptohan", description="CryptoHan — enkripsi & transfer file aman.")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("gui", help="Buka antarmuka grafis (default bila tanpa argumen).")
    sp.set_defaults(func=_cmd_gui)

    sp = sub.add_parser("encrypt", help="Enkripsi file.")
    sp.add_argument("infile")
    sp.add_argument("--algo", choices=["aes", "rsa"], default="aes")
    sp.add_argument("--out")
    sp.add_argument("--password")
    sp.add_argument("--password-stdin", action="store_true")
    sp.add_argument("--pubkey", help="Public key PEM (wajib untuk --algo rsa)")
    sp.set_defaults(func=_cmd_encrypt)

    sp = sub.add_parser("decrypt", help="Dekripsi file .enc (algoritma terbaca otomatis).")
    sp.add_argument("encfile")
    sp.add_argument("--out")
    sp.add_argument("--password")
    sp.add_argument("--password-stdin", action="store_true")
    sp.add_argument("--privkey", help="Private key PEM (wajib untuk file RSA-Hybrid)")
    sp.add_argument("--keypassword", help="Password untuk membuka private key, jika ada")
    sp.set_defaults(func=_cmd_decrypt)

    sp = sub.add_parser("keygen", help="Buat pasangan kunci baru.")
    sp.add_argument("--kind", choices=["rsa", "transport"], default="rsa")
    sp.add_argument("--priv", required=True)
    sp.add_argument("--pub", required=True)
    sp.add_argument("--password")
    sp.set_defaults(func=_cmd_keygen)

    sp = sub.add_parser("fingerprint", help="Tampilkan fingerprint sebuah file kunci .pem.")
    sp.add_argument("keyfile")
    sp.add_argument("--password")
    sp.set_defaults(func=_cmd_fingerprint)

    sp = sub.add_parser("send", help="Kirim file .enc ke IP penerima.")
    sp.add_argument("encfile")
    sp.add_argument("--host")
    sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    sp.add_argument("--contact", help="Ambil IP/port/fingerprint dari kontak tersimpan")
    sp.add_argument("--expect-fingerprint", help="Fingerprint hex penerima yang wajib cocok")
    sp.set_defaults(func=_cmd_send)

    sp = sub.add_parser("receive", help="Terima file (blocking; Ctrl+C untuk berhenti).")
    sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    sp.add_argument("--out-dir", required=True)
    sp.add_argument("--contact", help="Ambil fingerprint pin dari kontak tersimpan")
    sp.add_argument("--expect-fingerprint", help="Fingerprint hex pengirim yang wajib cocok")
    sp.add_argument("--auto-decrypt", action="store_true")
    sp.add_argument("--password", help="Password AES untuk auto-dekripsi")
    sp.add_argument("--privkey", help="Private key PEM untuk auto-dekripsi RSA-Hybrid")
    sp.add_argument("--keypassword", help="Password untuk membuka private key, jika ada")
    sp.set_defaults(func=_cmd_receive)

    sp = sub.add_parser("contacts", help="Kelola daftar kontak.")
    csub = sp.add_subparsers(dest="contacts_command", required=True)
    a = csub.add_parser("add"); a.add_argument("name"); a.add_argument("ip"); a.add_argument("port", type=int)
    a.add_argument("--fingerprint")
    r = csub.add_parser("remove"); r.add_argument("name")
    csub.add_parser("list")
    sp.set_defaults(func=_cmd_contacts)

    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        from .gui import launch_gui
        launch_gui()
        return 0
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except FingerprintMismatchError as e:
        print(f"Error keamanan: {e}", file=sys.stderr)
        return 2
    except (CryptoError, TransportError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
