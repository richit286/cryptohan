"""Enkripsi/dekripsi file streaming (chunked AEAD / STREAM construction)."""

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import secrets

from .config import (
    MAGIC, ALGO_AES, ALGO_RSA, ALGO_NAMES,
    PBKDF2_ITERS, SALT_LEN, NONCE_PREFIX_LEN, FILE_CHUNK,
    CryptoError,
)


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
