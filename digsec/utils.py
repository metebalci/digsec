# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
various utility functions
"""
from datetime import datetime
import os
import random
import sys
from digsec import dprint, DigsecError
from digsec.constants import DNS_CLASS_TO_INT, DNS_TYPE_TO_INT
from digsec.constants import DNS_CLASS_TO_STR, DNS_TYPE_TO_STR
from digsec.constants import DNS_OPCODE_TO_INT, DNS_RCODE_TO_INT
from digsec.constants import DNS_OPCODE_TO_STR, DNS_RCODE_TO_STR
from digsec.constants import DNSSEC_ALGORITHM_TO_INT, DNSSEC_DIGEST_TYPE_TO_INT
from digsec.constants import DNSSEC_ALGORITHM_TO_STR, DNSSEC_DIGEST_TYPE_TO_STR
from digsec.constants import DNSSEC_NSEC3_ALGORITHM_TO_INT
from digsec.constants import DNSSEC_NSEC3_ALGORITHM_TO_STR


def has_flag(flag):
    return len(list(filter(lambda x: x == flag, sys.argv))) > 0


def l2s(l):
    return '\n'.join(str(x) for x in l)


def format_ipv6_addr(addr_with_zeroes):
    fa = ''
    last_colon = False
    for c in addr_with_zeroes.split(':'):
        if c == '0000':
            if last_colon:
                pass
            else:
                last_colon = True
                fa = fa + ':'
        else:
            if len(fa) > 0:
                fa = fa + ':'
            fa = fa + c
    return fa


# RFC 4034
# this implementation is on purpose similar to a C code in
# RFC 4034 Appendix B Key Tag Calculation
def calculate_keytag(rdata):
    key = rdata
    keysize = len(rdata)
    ac = 0
    for i in range(0, keysize):
        if (i & 1) != 0:
            ac += key[i]
        else:
            ac += (key[i] << 8)
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


# generate a random unsigned short id to use in DNS Messages
def random_dns_message_id():
    return random.randint(0, 2 << 16) & 0xFFFF


# returns (list of qname parts, offset_to_continue)
# handles message compression: see RFC 1035 Section 4.1.4
# qname is either:
# - sequence of labels ending with zero
# - a pointer (to a sequence of labels)
# - a sequence of labels ending with a pointer
# thus zero or a pointer terminates this process
# p here is the full dns packet because message compression
# may refer to anywhere in the package
def decode_labels(p, offset):
    i = offset
    qnameparts = []
    while True:
        qnamepartlen = p[i]
        dprint('qnamepartlen: %d' % qnamepartlen)
        i = i + 1
        if qnamepartlen == 0:
            # termination
            # it might look like it may be OK to not add empty label here
            # and do not use len(qnameparts)-1 in validate
            # but it causes an error if presentation format is read
            # because names are given with root (dots)
            qnameparts.append('')
            break
        if qnamepartlen & 0b11000000 == 0:
            # no message compression
            # this is a normal qname part
            qnamepart = p[i:i + qnamepartlen]
            i = i + qnamepartlen
            label = qnamepart.decode('ascii')
            dprint('label: %s' % label)
            qnameparts.append(label)
        elif qnamepartlen & 0b11000000 == 0b11000000:
            # message compression
            # this is a pointer to another label
            # make an unsigned 14-bit number
            pointer = ((qnamepartlen & 0b00111111) << 8) | p[i]
            i = i + 1
            (pointedlabels, _pointedoffset) = decode_labels(p, pointer)
            dprint('pointed labels: %s' % pointedlabels)
            # pointed part can be full or partial
            qnameparts.extend(pointedlabels)
            # pointed part can be only the last, so
            # we return from here
            return (qnameparts, i)
        else:
            assert False, "invalid qnamepartlen: 0x%x" % qnamepartlen
    return (qnameparts, i)

# banme
def decode_name(p, offset):
    (labels, newoffset) = decode_labels(p, offset)
    return ('.'.join(labels), newoffset)


def encode_name(name):
    b = bytearray()
    for label in name.split("."):
        b.append(len(label))
        b.extend(label.encode('ascii'))
    return b


def format_as_other(an_int):
    return 'OTHER(%d)' % an_int


def dns_class_to_int(class_as_str):
    return DNS_CLASS_TO_INT[class_as_str]


def dns_class_to_str(class_as_int):
    return DNS_CLASS_TO_STR.get(class_as_int, 'CLASS%d' % class_as_int)


def dns_type_to_int(type_as_str):
    return DNS_TYPE_TO_INT[type_as_str]


def dns_type_to_str(type_as_int):
    return DNS_TYPE_TO_STR.get(type_as_int, 'TYPE%d' % type_as_int)


def dns_opcode_to_int(opcode_as_str):
    return DNS_OPCODE_TO_INT[opcode_as_str]


def dns_opcode_to_str(opcode_as_int):
    return DNS_OPCODE_TO_STR.get(opcode_as_int, format_as_other(opcode_as_int))


def dns_rcode_to_str(rcode_as_int):
    return DNS_RCODE_TO_STR.get(rcode_as_int, format_as_other(rcode_as_int))


def dns_rcode_to_int(rcode_as_str):
    return DNS_RCODE_TO_INT[rcode_as_str]


def dnssec_algorithm_to_int(algo_as_mnemonic):
    return DNSSEC_ALGORITHM_TO_INT[algo_as_mnemonic]


def dnssec_algorithm_to_str(algo_as_int):
    return DNSSEC_ALGORITHM_TO_STR.get(
        algo_as_int,
        format_as_other(algo_as_int))


def dnssec_digest_type_to_int(digest_as_mnemonic):
    return DNSSEC_DIGEST_TYPE_TO_INT[digest_as_mnemonic]


def dnssec_digest_type_to_str(digest_as_int):
    return DNSSEC_DIGEST_TYPE_TO_STR.get(digest_as_int,
                                         format_as_other(digest_as_int))


def dnssec_nsec3_algorithm_to_int(mnemonic):
    return DNSSEC_NSEC3_ALGORITHM_TO_INT[mnemonic]


def dnssec_nsec3_algorithm_to_str(num):
    return DNSSEC_NSEC3_ALGORITHM_TO_STR.get(num,
                                             format_as_other(num))


def set_eq_flag(flags, s, flag_name, default, conv):
    dprint('set_eq_flag, s: %s, flag_name: %s, default: %s' % (s,
                                                               flag_name,
                                                               default))
    if s.startswith(flag_name):
        st = s.split('=')
        if len(st) == 1:
            if flag_name in flags:
                if default is not None:
                    flags[flag_name] = default
                else:
                    raise DigsecError('Flag %s requires an ' \
                                      'explicit value after =' % flag_name)
            else:
                raise DigsecError('Flag %s not expected here.' % flag_name)
        else:
            if flag_name in flags:
                dprint('st: %s' % st[1])
                flags[flag_name] = conv(st[1])
            else:
                raise DigsecError('Flag %s not expected here.' % flag_name)
        return True

    return False


# pylint: disable=too-many-nested-blocks
# pylint: disable=too-many-branches
def parse_flags(argv, default_flags):
    flags = default_flags
    # adding debug and help here to not raise error later
    if 'debug' not in flags:
        flags['debug'] = False
    if 'help' not in flags:
        flags['help'] = False
    for flag in argv:
        dprint('parsing flag: %s' % flag)
        if flag[0] == '+':
            flag = flag[1:]
            # these are flags with =, so with a value
            if set_eq_flag(flags,
                           flag,
                           'udp_payload_size',
                           None,
                           int):
                continue

            if set_eq_flag(flags,
                           flag,
                           'timeout',
                           None,
                           float):
                continue

            if set_eq_flag(flags,
                           flag,
                           'save-root-anchors',
                           'root-anchors.xml',
                           str):
                continue

            if set_eq_flag(flags,
                           flag,
                           'root-anchors-location',
                           'https://data.iana.org/root-anchors/',
                           str):
                continue

            if set_eq_flag(flags,
                           flag,
                           'save-ds-anchors',
                           '_root.IN',
                           str):
                continue

            if set_eq_flag(flags,
                           flag,
                           'save-answer-prefix',
                           None,
                           str):
                continue

            if set_eq_flag(flags,
                           flag,
                           'save-packets',
                           None,
                           str):
                continue

            if set_eq_flag(flags,
                           flag,
                           'save-answer-dir',
                           None,
                           str):
                continue

            val = True
            if flag[0:2] == 'no':
                val = False
                flag = flag[3:]
            found = False
            for f in ['rd',
                      'cd',
                      'do',
                      'tcp',
                      'debug',
                      'help',
                      'save-answer',
                      'show-file-contents',
                      'show-protocol',
                      'show-friendly']:
                if flag == f:
                    if f in flags:
                        flags[f] = val
                        found = True
                        break
                    raise DigsecError('Flag %s not expected here.' % flag)
            if not found:
                raise DigsecError('Flag %s unknown.' % flag)
    return flags


# get matching DNS keys
# pylint: disable=too-many-arguments
def get_dnskeys(dnskey_rrset, keytag, algorithm, name, sep, zsk):
    """
    Find the DNSKEY with keytag, algorithm, name

    dnskey_rrset --
    keytag --
    algorithm --
    name --
    sep -- None, dont check, False/True check against
    zsk -- None, dont check, False/True check against
    """

    dnskeys = list(filter(lambda x: x.keytag == keytag,
                          dnskey_rrset))
    if len(dnskeys) == 0:
        raise DigsecError('No DNSKEY with keytag: %s' % keytag)

    dnskeys = list(filter(lambda x: x.algorithm == algorithm,
                          dnskeys))

    if len(dnskeys) == 0:
        raise DigsecError('No DNSKEY with keytag: %s, algorithm: %d' % (
            keytag,
            algorithm))

    dnskeys = list(filter(lambda x: x.name == name,
                          dnskeys))

    if len(dnskeys) == 0:
        raise DigsecError('No DNSKEY with keytag: %s, algorithm: %s, ' \
                          'name: %s' % (
                              keytag,
                              algorithm,
                              name))

    if sep is not None:
        if sep:
            dnskeys = list(filter(lambda x: x.sep, dnskeys))
        else:
            dnskeys = list(filter(lambda x: not x.sep, dnskeys))

    if zsk is not None:
        if zsk:
            dnskeys = list(filter(lambda x: x.zone_key, dnskeys))
        else:
            dnskeys = list(filter(lambda x: not x.zone_key, dnskeys))

    if len(dnskeys) == 0:
        raise DigsecError('No DNSKEYs with keytag: %s, algorithm: %d, ' \
                          'name: %s, SEP: %s, ZSK: %s' % (keytag,
                                                          algorithm,
                                                          name,
                                                          sep,
                                                          zsk))

    return dnskeys


def ensure_single_name_type_class_in_rrset(rrset):
    an_rr = None
    for rr in rrset:
        if an_rr is None:
            an_rr = rr
        if rr.name != an_rr.name:
            raise DigsecError('RRSET contains different names')
        if rr.typ != an_rr.typ:
            raise DigsecError('RRSET contains different types')
        if rr.clas != an_rr.clas:
            raise DigsecError('RRSET contains different classes')

# RFC 4035: Section 5.3.1: Checking the RRSIG RR Validity
# This method exactly follows the rules in above section of this RFC
def check_rrsig_rr_validity(rrsig, rrset, zone, dnskey_rrset):
    for rr in rrset:
        if rrsig.name != rr.name:
            raise DigsecError('RRSIG (%s) and RRSET (%s) have different ' \
                              'owner name' % (rrsig.name,
                                              rr.name))
        if rrsig.clas != rr.clas:
            raise DigsecError('RRSIG (%s) and RRSET (%s) have different ' \
                              'class' % (rrsig.clas,
                                         rr.clas))
        if rrsig.signers_name != zone:
            raise DigsecError('RRSIG signers name (%s) is different than ' \
                              'the zone (%s)' % (rrsig.signers_name,
                                                 zone))
        if rrsig.type_covered != rr.typ:
            raise DigsecError('RRSIG type covered (%s) is different than ' \
                              'RRSET type (%s)' % (rrsig.type_covered,
                                                   rrset.typ))
        # . is counted as zero label, com is 1, metebalci.com is 2 etc.
        # so len(split result) is +1
        if len(rr.name.split('.')) < rrsig.labels:
            raise DigsecError('# labels of RRSET name (%s) < ' \
                              'RRSIG labels (%d)' % (rr.name.split('.'),
                                                     rrsig.labels))
    now = datetime.now()
    if now > rrsig.signature_expiration:
        raise DigsecError('RRSIG is not valid anymore ' \
                          '(now > signature expiration)')
    if now < rrsig.signature_inception:
        raise DigsecError('RRSIG is not valid yet ' \
                          '(now < signature inception)')
    # this checks if there is a DNSKEY matching
    # RRSIG's signers_name, algorithm, keytag and zone flag bit set
    # this is also called in validate but this is for the sake of followint
    # the same conditions in the RFC
    get_dnskeys(dnskey_rrset,
                rrsig.keytag,
                rrsig.algorithm,
                rrsig.signers_name,
                None,
                True)


def ensure_file_exists(filename):
    if not os.path.isfile(filename):
        raise DigsecError('file does not exist: %s' % filename)
