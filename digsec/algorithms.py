# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
helpers for using algorithms
"""
import hashlib
import rsa
from ecdsa import VerifyingKey, NIST256p, NIST384p, BadSignatureError
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey
from ecpy.ecdsa import ECDSA
from digsec import DigsecError


def get_algorithm(algorithm_mnemonic):
    algo = __dnssec_algorithms.get(algorithm_mnemonic, None)
    if algo is None:
        raise DigsecError('algorithm: %s is not supported' % algorithm_mnemonic)
    return algo


def get_digest(digest_mnemonic):
    digest = __dnssec_digests.get(digest_mnemonic, None)
    if digest is None:
        raise DigsecError('digest: %s is not supported' % digest_mnemonic)
    return digest

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


# signature is 64-octet
def ed25519(data, signature, dnskey):
    (sign_of_x, y) = dnskey.ed25519_curve_point()
    curve = Curve.get_curve('Ed25519')
    x = curve.x_recover(y, sign_of_x)
    pubkey = ECPublicKey(Point(x, y, curve, True))
    signer = ECDSA()
    return signer.verify(data, signature, pubkey)


# signature is 114-octet
def ed448(data, signature, dnskey):
    (sign_of_x, y) = dnskey.ed448_curve_point()
    curve = Curve.get_curve('Ed448')
    x = curve.x_recover(y, sign_of_x)
    pubkey = ECPublicKey(Point(x, y, curve, True))
    signer = ECDSA()
    return signer.verify(data, signature, pubkey)


__dnssec_algorithms = {}
__dnssec_algorithms['RSASHA1'] = rsasha1
__dnssec_algorithms['RSASHA1-NSEC3-SHA1'] = rsasha1
__dnssec_algorithms['RSASHA256'] = rsasha256
__dnssec_algorithms['RSASHA512'] = rsasha512
__dnssec_algorithms['ECDSAP256SHA256'] = ecdsap256sha256
__dnssec_algorithms['ECDSAP384SHA256'] = ecdsap384sha384
__dnssec_algorithms['ED25519'] = ed25519
__dnssec_algorithms['ED448'] = ed448


__dnssec_digests = {}
__dnssec_digests['SHA-1'] = sha1
__dnssec_digests['SHA-256'] = sha256
__dnssec_digests['SHA-384'] = sha384
