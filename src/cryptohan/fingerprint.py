"""Fingerprint kunci publik (kata/hex/numerik) untuk verifikasi anti-MITM."""

import hashlib

from .keys import canonical_public_bytes

WORDS = [
    "able","acid","aged","army","atom","aunt","back","bake","band","bare","barn","base","bath","bean","bear","beat",
    "beef","bell","belt","bend","best","bird","bite","blue","boat","body","bold","bolt","bone","book","boot","born",
    "boss","both","bowl","brave","bread","brick","broom","brown","brush","bulk","bull","bump","bunk","burn","bush","busy",
    "cake","calm","camp","cane","card","care","cart","case","cash","cave","cell","chat","chef","chin","chip","city",
    "clap","claw","clay","clip","club","coal","coat","code","coin","cold","cook","cool","cord","core","cork","corn",
    "cost","crab","crew","crop","crow","cube","curl","dark","dawn","deal","deck","deep","deer","desk","dial","dice",
    "dine","dish","dive","dock","dome","door","dose","dove","down","drag","draw","drip","drop","drum","duck","dull",
    "dust","duty","each","earn","east","easy","edge","epic","even","ever","exit","face","fact","fade","fair","fall",
    "fame","farm","fast","fate","fear","feed","feel","fern","file","fill","film","find","fine","fire","firm","fish",
    "five","flag","flap","flat","flee","flew","flip","flow","foam","fold","folk","font","food","foot","fork","form",
    "fort","four","free","frog","fuel","full","fund","gain","game","gate","gear","gift","girl","give","glad","glow",
    "glue","goal","goat","gold","golf","gone","good","gray","grid","grim","grin","grip","grow","gulf","hair","half",
    "hall","hand","hang","hard","harm","hawk","haze","head","heal","heap","hear","heat","herb","herd","hero","hide",
    "high","hill","hint","hive","hold","hole","holy","home","hood","hook","hope","horn","host","hour","huge","hull",
    "hunt","hurt","hush","icon","idea","inch","iron","item","jade","jail","jazz","join","joke","jump","june","junk",
    "keen","keep","kick","kind","king","kiss","kite","knee","knot","lace","lack","lady","lake","lamp","lane","last",
]
assert len(WORDS) == 256 and len(set(WORDS)) == 256


def fp_digest(pb): return hashlib.sha256(pb).digest()
def fp_hex_full(pb): return fp_digest(pb).hex()
def fp_words(pb, n=8): return " ".join(WORDS[b] for b in fp_digest(pb)[:n])


def fp_hex(pb, nbytes=16, group=2):
    h = fp_digest(pb)[:nbytes].hex().upper()
    return " ".join(h[i:i + group * 2] for i in range(0, len(h), group * 2))


def fp_numeric(pb, nbytes=8, group=5):
    d = str(int.from_bytes(fp_digest(pb)[:nbytes], "big")).zfill(nbytes * 3)
    return " ".join(d[i:i + group] for i in range(0, len(d), group))


def fp_card(pb):
    return (f"  Kata    : {fp_words(pb)}\n"
            f"  Hex     : {fp_hex(pb)}\n"
            f"  Numerik : {fp_numeric(pb)}")


def fp_key_card(path, password=None):
    return fp_card(canonical_public_bytes(path, password))
