# Verifies which SKID method each test certificate uses.
# pip install cryptography
#
# Usage: python3 classify.py *.pem

import sys, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec as ec_mod


def spk_bytes(cert):
    """Extract the subjectPublicKey BIT STRING content (no ASN.1 wrapper)."""
    spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def read_tl(b, i):
        tag = b[i]; i += 1
        n = b[i]; i += 1
        if n >= 0x80:
            k = n & 0x7F; n = int.from_bytes(b[i:i+k], "big"); i += k
        return tag, n, i

    _, _, i = read_tl(spki_der, 0)
    _, ln, i2 = read_tl(spki_der, i)
    i2 += ln
    _, ln, i3 = read_tl(spki_der, i2)
    return spki_der[i3 + 1 : i3 + ln]


def rsa_modulus_bytes(cert):
    pub = cert.public_key()
    if not isinstance(pub, rsa_mod.RSAPublicKey):
        return None
    n = pub.public_numbers().n
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def classify(cert):
    try:
        actual = cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
    except x509.ExtensionNotFound:
        return "no_skid"

    spk = spk_bytes(cert)
    if actual == hashlib.sha1(spk).digest():
        return "RFC5280"
    if actual == hashlib.sha256(spk).digest()[:20]:
        return "RFC7093"

    mod = rsa_modulus_bytes(cert)
    if mod is not None:
        if actual == hashlib.sha1(mod).digest():
            return "LibraryGoSha1"
        if actual == hashlib.sha256(mod).digest()[:20]:
            return "LibraryGoSha256"

    return "unknown"


for path in sys.argv[1:]:
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    pub = cert.public_key()
    key_type = "RSA" if isinstance(pub, rsa_mod.RSAPublicKey) else "EC" if isinstance(pub, ec_mod.EllipticCurvePublicKey) else "?"
    print(f"{path}: {classify(cert)} ({key_type}, {cert.subject.rfc4514_string()})")
