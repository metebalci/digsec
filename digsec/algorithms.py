import hashlib
import rsa
import binascii


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


def rsasha1(data, signature, dnskey):
    exponent, modulus = dnskey.rsasha1_public_key()
    pk = rsa.PublicKey(modulus, exponent)
    return rsa.verify(data, signature, pk)


def rsasha256(data, signature, dnskey):
    exponent, modulus = dnskey.rsasha256_public_key()
    pk = rsa.PublicKey(modulus, exponent)
    return rsa.verify(data, signature, pk)


dnssec_algorithms = {}
dnssec_algorithms['RSASHA1'] = rsasha1
dnssec_algorithms['RSASHA256'] = rsasha256

dnssec_digests = {}
dnssec_digests['SHA-1'] = sha1
dnssec_digests['SHA-256'] = sha256
