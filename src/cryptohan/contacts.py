"""Kontak (HMAC-protected)."""

import os
import json
import hmac
import hashlib
import secrets

from .config import ensure_identity_dir, secure_chmod


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
