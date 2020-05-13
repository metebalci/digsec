import hashlib
import rsa
import binascii
from ecdsa import VerifyingKey, NIST256p, NIST384p


def hash_common(m, data, digest):
    m.update(data)
    calculated_digest = m.digest()
    assert len(calculated_digest) == len(digest)
    return calculated_digest == digest


def sha1(data, digest):
    return hash_common(hashlib.sha1(),
                       data,
                       digest)


def sha256(data, digest):
    return hash_common(hashlib.sha256(),
                       data,
                       digest)


def sha384(data, digest):
    return hash_common(hashlib.sha384(),
                       data,
                       digest)


def rsasha1(data, signature, dnskey):
    exponent, modulus = dnskey.rsasha1_public_key()
    pk = rsa.PublicKey(modulus, exponent)
    return rsa.verify(data, signature, pk)


def rsasha256(data, signature, dnskey):
    exponent, modulus = dnskey.rsasha256_public_key()
    pk = rsa.PublicKey(modulus, exponent)
    return rsa.verify(data, signature, pk)


def rsasha512(data, signature, dnskey):
    exponent, modulus = dnskey.rsasha512_public_key()
    pk = rsa.PublicKey(modulus, exponent)
    return rsa.verify(data, signature, pk)


def ecdsap256sha256(data, signature, dnskey):
    q_uncompressed_bytes = dnskey.ecdsap256sha256_curve_point()
    q = VerifyingKey.from_string(q_uncompressed_bytes,
                                 curve=NIST256p,
                                 hashfunc=hashlib.sha256)
    try:
        # this uses the default_hashfunc set above
        q.verify(signature, data)
        return True
    except BadSignatureError:
        return False


def ecdsap384sha384(data, signature, dnskey):
    q_uncompressed_bytes = dnskey.ecdsap384sha384_curve_point()
    q = VerifyingKey.from_string(q_uncompressed_bytes,
                                 curve=NIST384p,
                                 hashfunc=hashlib.sha384)
    try:
        # this uses the default_hashfunc set above
        q.verify(signature, data)
        return True
    except BadSignatureError:
        return False


dnssec_algorithms = {}
dnssec_algorithms['RSASHA1'] = rsasha1
dnssec_algorithms['RSASHA256'] = rsasha256
dnssec_algorithms['RSASHA512'] = rsasha512
dnssec_algorithms['ECDSAP256SHA256'] = ecdsap256sha256
dnssec_algorithms['ECDSAP384SHA256'] = ecdsap384sha384


dnssec_digests = {}
dnssec_digests['SHA-1'] = sha1
dnssec_digests['SHA-256'] = sha256
dnssec_digests['SHA-384'] = sha384
