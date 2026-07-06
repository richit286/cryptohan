import os

from cryptohan.keys import (
    generate_rsa_keypair, load_public_key, load_private_key, canonical_public_bytes,
    generate_transport_identity, load_transport_private_raw,
    transport_public_raw_from_private, ensure_transport_identity,
)


def test_rsa_keypair_roundtrip(tmp_path):
    priv = str(tmp_path / "k.priv.pem")
    pub = str(tmp_path / "k.pub.pem")
    generate_rsa_keypair(priv, pub)
    assert load_public_key(pub) is not None
    assert load_private_key(priv) is not None


def test_canonical_public_bytes_matches_from_priv_and_pub(tmp_path):
    priv = str(tmp_path / "k.priv.pem")
    pub = str(tmp_path / "k.pub.pem")
    generate_rsa_keypair(priv, pub, password="pw123")
    assert canonical_public_bytes(pub) == canonical_public_bytes(priv, password="pw123")


def test_transport_identity_roundtrip(tmp_path):
    priv = str(tmp_path / "t.priv.pem")
    pub = str(tmp_path / "t.pub.pem")
    generate_transport_identity(priv, pub)
    raw = load_transport_private_raw(priv)
    assert len(raw) == 32
    pub_raw = transport_public_raw_from_private(raw)
    assert len(pub_raw) == 32


def test_ensure_transport_identity_idempotent(isolated_identity_dir):
    priv1, pub1 = ensure_transport_identity()
    raw1 = load_transport_private_raw(priv1)
    priv2, pub2 = ensure_transport_identity()
    raw2 = load_transport_private_raw(priv2)
    assert priv1 == priv2 and pub1 == pub2
    assert raw1 == raw2
    assert os.path.exists(priv1) and os.path.exists(pub1)
