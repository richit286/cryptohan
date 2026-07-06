import pytest

import cryptohan.config as config
import cryptohan.logging_setup as logging_setup
from cryptohan.keys import generate_rsa_keypair


@pytest.fixture
def isolated_identity_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "IDENTITY_DIR", str(tmp_path / ".cryptohan"))
    logging_setup._LOGGER = None
    yield tmp_path
    logging_setup._LOGGER = None


@pytest.fixture
def rsa_keypair(tmp_path):
    priv = tmp_path / "k.priv.pem"
    pub = tmp_path / "k.pub.pem"
    generate_rsa_keypair(str(priv), str(pub))
    return str(priv), str(pub)
