import os

from cryptohan.cli import main


def test_keygen_and_fingerprint(tmp_path, capsys):
    priv = str(tmp_path / "k.priv.pem")
    pub = str(tmp_path / "k.pub.pem")
    rc = main(["keygen", "--kind", "rsa", "--priv", priv, "--pub", pub])
    assert rc == 0
    assert os.path.exists(priv) and os.path.exists(pub)

    rc = main(["fingerprint", pub])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Kata" in out and "Hex" in out


def test_encrypt_decrypt_roundtrip_aes(tmp_path):
    src = tmp_path / "data.txt"
    src.write_text("rahasia perusahaan")
    enc = str(tmp_path / "data.enc")
    out = str(tmp_path / "data.out")

    rc = main(["encrypt", str(src), "--algo", "aes", "--password", "pw123", "--out", enc])
    assert rc == 0
    rc = main(["decrypt", enc, "--password", "pw123", "--out", out])
    assert rc == 0
    assert open(out).read() == "rahasia perusahaan"


def test_decrypt_wrong_password_returns_nonzero(tmp_path, capsys):
    src = tmp_path / "data.txt"
    src.write_text("data")
    enc = str(tmp_path / "data.enc")
    main(["encrypt", str(src), "--algo", "aes", "--password", "pw123", "--out", enc])
    rc = main(["decrypt", enc, "--password", "wrong", "--out", str(tmp_path / "out.txt")])
    assert rc == 1


def test_contacts_add_list_remove(isolated_identity_dir, capsys):
    assert main(["contacts", "add", "alice", "10.0.0.1", "5000", "--fingerprint", "deadbeef"]) == 0
    capsys.readouterr()
    assert main(["contacts", "list"]) == 0
    out = capsys.readouterr().out
    assert "alice" in out and "10.0.0.1:5000" in out
    assert main(["contacts", "remove", "alice"]) == 0
    capsys.readouterr()
    assert main(["contacts", "list"]) == 0
    out = capsys.readouterr().out
    assert "alice" not in out
