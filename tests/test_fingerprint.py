from cryptohan.fingerprint import WORDS, fp_digest, fp_words, fp_hex, fp_numeric, fp_card, fp_key_card


def test_wordlist_integrity():
    assert len(WORDS) == 256
    assert len(set(WORDS)) == 256


def test_determinism():
    data = b"some fixed public key bytes for testing determinism"
    assert fp_digest(data) == fp_digest(data)
    assert fp_words(data) == fp_words(data)
    assert fp_hex(data) == fp_hex(data)
    assert fp_numeric(data) == fp_numeric(data)


def test_different_input_differs():
    a = fp_digest(b"input-one")
    b = fp_digest(b"input-two")
    assert a != b


def test_fp_card_contains_all_labels():
    card = fp_card(b"some public key bytes")
    assert "Kata" in card and "Hex" in card and "Numerik" in card


def test_fp_key_card_from_keypair(rsa_keypair):
    priv_path, pub_path = rsa_keypair
    card = fp_key_card(pub_path)
    assert "Kata" in card
    assert fp_key_card(pub_path) == fp_key_card(priv_path)
