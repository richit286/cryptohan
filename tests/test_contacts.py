from cryptohan.contacts import (
    load_contacts, upsert_contact, remove_contact, _contacts_path,
)


def test_missing_file_returns_empty_ok(isolated_identity_dir):
    data, ok = load_contacts()
    assert data == [] and ok is True


def test_upsert_add_and_update(isolated_identity_dir):
    upsert_contact("alice", "10.0.0.1", 5000, fingerprint="deadbeef")
    data, ok = load_contacts()
    assert ok is True
    assert data == [{"name": "alice", "ip": "10.0.0.1", "port": 5000, "fingerprint": "deadbeef"}]

    upsert_contact("alice", "10.0.0.2", 6000)
    data, _ = load_contacts()
    assert data[0]["ip"] == "10.0.0.2" and data[0]["port"] == 6000
    assert data[0]["fingerprint"] == "deadbeef"          # fingerprint preserved when not overwritten


def test_remove_contact(isolated_identity_dir):
    upsert_contact("bob", "10.0.0.5", 1234)
    remove_contact("bob")
    data, ok = load_contacts()
    assert data == [] and ok is True


def test_tamper_detection(isolated_identity_dir):
    upsert_contact("alice", "10.0.0.1", 5000)
    # rewrite contacts.json directly, bypassing save_contacts() -> contacts.mac stays stale
    with open(_contacts_path(), "wb") as f:
        f.write(b'[{"name": "mallory", "ip": "6.6.6.6", "port": 1}]')
    data, ok = load_contacts()
    assert ok is False
    assert data[0]["name"] == "mallory"                  # data still parsed; caller must check ok
