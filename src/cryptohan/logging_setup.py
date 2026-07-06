"""Logging (tidak pernah mencatat password/kunci)."""

import os
import logging
import logging.handlers

from .config import APP_NAME, ensure_identity_dir, secure_chmod

_LOGGER = None


def get_logger():
    global _LOGGER
    if _LOGGER:
        return _LOGGER
    lg = logging.getLogger(APP_NAME); lg.setLevel(logging.INFO); lg.propagate = False
    path = os.path.join(ensure_identity_dir(), "cryptohan.log")
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=512 * 1024,
                                              backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                      "%Y-%m-%d %H:%M:%S"))
    lg.addHandler(fh); secure_chmod(path); _LOGGER = lg
    return lg
