# coding: utf-8
# pylint: disable=invalid-name
# pylint: disable=missing-function-docstring
"""
handles validate command
"""
import binascii
from digsec import dprint, DigsecError
from digsec.algorithms import get_algorithm, get_digest
from digsec.help import display_help_validate
from digsec.utils import parse_flags, get_dnskeys
from digsec.utils import ensure_single_name_type_class_in_rrset
from digsec.utils import check_rrsig_rr_validity
from digsec.utils import ensure_file_exists
from digsec.answer import print_answer_file, read_answer_file


def validate_rrsig(rrset,
                   rrsig,
                   dnskey_rrset):
    """
    Validate rrsig of rrset with dnskey_rrset.

    If rrset contains DNSKEY records, rrset equals to dnskey_rrset.

    Arguments:
        rrset -- list of L2 records of any type
        rrsig -- L2 RRSIG record
        dnskey_rrset -- list of L2 DNSKEY records containing the ZSK

    Returns:
        (True, dnskey) -- if rrsig can be validated with any dnskey
        (False, None) -- if rrsig cannot be validated
    """

    dnskeys = get_dnskeys(dnskey_rrset,
                          rrsig.keytag,
                          rrsig.algorithm,
                          rrsig.signers_name,
                          None,
                          True)

    # RFC 4034 Section 6.2
    # canonical form with original TTL, names changed to lowercase etc.
    canonical_rrset = map(lambda rr: rr.canonical_l1(rrsig.original_ttl),
                          rrset)

    # RFC 4034 Section 6.3
    # sorted by RDATA
    canonical_rrset = sorted(canonical_rrset,
                             key=lambda x: binascii.hexlify(x.rdata))

    # RFC 4034 Section 3.1.8.1
    # signature calculation
    # sign(RRSIG.RDATA | CANONICAL_RR1 | CANONICAL_R2 | ...)
    signed_data = bytearray()
    signed_data.extend(rrsig.rrsig_rdata)

    for canonical_rr in canonical_rrset:
        signed_data.extend(canonical_rr.to_packet())

    dprint('Signed Data (RRSIG + canonical RRSET): 0x%s' %
           binascii.hexlify(signed_data).decode('ascii'))

    verification_algorithm = get_algorithm(rrsig.algorithm)

    # according to RFC 4035: Section 5.3.1
    # It is possible for more than one DNSKEY RR to match the conditions
    # above.  In this case, the validator cannot predetermine which DNSKEY
    # RR to use to authenticate the signature, and it MUST try each
    # matching DNSKEY RR until either the signature is validated or the
    # validator has run out of matching public keys to try.

    for dnskey in dnskeys:
        verified = verification_algorithm(bytes(signed_data),
                                          bytes(rrsig.signature),
                                          dnskey)
        if verified:
            return True, dnskey

    return False, None


def validate_dnskey(dnskey, ds):
    """
    Validate dnskey with ds.

    Arguments:
        dnskey -- L2 DNSKEY record
        ds -- L2 DS record

    Returns:
        True -- if ds contains a valid digest of dnskey
        False -- if not
    """

    dprint('Hashed Data (DNSKEY NAME + DNSKEY RDATA): 0x%s' %
           binascii.hexlify(dnskey.digest_data).decode('ascii'))

    verification_algorithm = get_digest(ds.digest_type)

    verified = verification_algorithm(dnskey.digest_data, ds.digest)

    return verified


# pylint: disable=too-many-branches
# This is the main validate call, which calls validate_rrsig and _dnskey
def validate(rrset,
             rrsig,
             dnskey_or_ds_rrset):
    """
    Validates non-DNSKEY rrset with rrsig using DNSKEY rrset or
              DNSKEY rrset with rrsig using DS rrset

    rrset -- list of L2 records of any type
    rrsig -- L2 RRSIG record
    dnskey_or_ds_rrset -- list of DNSKEY or DS L2 records
    """

    ensure_single_name_type_class_in_rrset(rrset)
    ensure_single_name_type_class_in_rrset(dnskey_or_ds_rrset)

    if rrsig.type_covered == 'DNSKEY':
        ds_rrset = []
        for rr in dnskey_or_ds_rrset:
            if rr.typ != 'DS':
                raise DigsecError('RRSIG covers DNSKEY, ' \
                                  'but %s provided not DS' % rr.typ)
            ds_rrset.append(rr)
        # also set dnskey_rrset because it also going to be used
        # by first validate_rrsig just below
        dnskey_rrset = rrset
    else:
        dnskey_rrset = []
        for rr in dnskey_or_ds_rrset:
            if rr.typ != 'DNSKEY':
                raise DigsecError('RRSIG covers %s, but %s provided ' \
                                  'not DNSKEY' % (rrsig.type_covered,
                                                  rr.typ))
            dnskey_rrset.append(rr)

    # not sure about this
    zone = dnskey_rrset[0].name
    check_rrsig_rr_validity(rrsig, rrset, zone, dnskey_rrset)

    # all RRSIG is signed with DNSKEY, also RRSIG.DNSKEY
    # but when it is RRSIG.DNSKEY, the digest of DNSKEY
    # also has to be checked against the DS
    valid, dnskey_signed_rrsig = validate_rrsig(rrset,
                                                rrsig,
                                                dnskey_rrset)

    if valid:
        dprint('OK: SIGNATURE VALID: RRSIG(%s,%s) ' \
               'with DNSKEY(%d,%s)' % (rrsig.type_covered,
                                       rrsig.algorithm,
                                       dnskey_signed_rrsig.keytag,
                                       dnskey_signed_rrsig.algorithm))
    else:
        raise DigsecError('NOK: SIGNATURE INVALID: RRSIG(%s,%s) ' \
                          'with DNSKEY(%d,%s)' % (rrsig.type_covered,
                                                  rrsig.algorithm,
                                                  dnskey_signed_rrsig.keytag,
                                                  dnskey_signed_rrsig.algorithm))

    if rrsig.type_covered == 'DNSKEY':
        # checking the dnskey signed RRSIG is same as the one
        # having the digest in DS
        dprint(ds_rrset)
        selected_ds_list = []
        for ds in ds_rrset:
            if ds.keytag == dnskey_signed_rrsig.keytag:
                selected_ds_list.append(ds)
        if len(selected_ds_list) == 0:
            raise DigsecError('no DS for DNSKEY with keytag: %d' %
                              dnskey_signed_rrsig.keytag)
        for ds in selected_ds_list:
            valid = validate_dnskey(dnskey_signed_rrsig, ds)
            if valid:
                dprint('OK: DIGEST VALID: DNSKEY(%d,%s) ' \
                       'with DS(%s)' % (ds.keytag,
                                        ds.algorithm,
                                        ds.digest_type))
                return
        raise DigsecError('NOK: NO VALID DIGEST FOUND ' \
                          'FOR DNSKEY(%d,%s)' % (ds.keytag,
                                                 ds.algorithm))


# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=too-many-statements
def do_validate(argv):
    """Run validate command."""
    if len(argv) < 3:
        display_help_validate()
    non_plus = list(filter(lambda x: x[0] != '+', argv))
    dprint(non_plus)
    if len(non_plus) != 3:
        raise DigsecError('Missing arguments, see usage')
    else:
        an_rrset_filename = non_plus[0]
        ensure_file_exists(an_rrset_filename)
        corresponding_rrsig_filename = non_plus[1]
        ensure_file_exists(corresponding_rrsig_filename)
        dnskey_or_ds_rrset_filename = non_plus[2]
        ensure_file_exists(dnskey_or_ds_rrset_filename)
    default_flags = {'show-file-contents': False}
    flags = parse_flags(argv[3:], default_flags)
    dprint(flags)
    an_rrset = read_answer_file(an_rrset_filename)
    corresponding_rrsig_rrset = read_answer_file(corresponding_rrsig_filename)
    dnskey_or_ds_rrset = read_answer_file(dnskey_or_ds_rrset_filename)
    if flags['show-file-contents']:
        print_answer_file(an_rrset_filename)
        print_answer_file(corresponding_rrsig_filename)
        print_answer_file(dnskey_or_ds_rrset_filename)
    if len(an_rrset) == 0:
        print_answer_file(an_rrset_filename)
        raise DigsecError('no RR in the %s file' % an_rrset_filename)
    if len(corresponding_rrsig_rrset) == 0:
        print_answer_file(corresponding_rrsig_filename)
        raise DigsecError('no RRSIG in the %s file' % corresponding_rrsig_filename)
    if len(corresponding_rrsig_rrset) > 1:
        print_answer_file(corresponding_rrsig_filename)
        raise DigsecError('multiple (>1) RRSIG in the %s file' %
                          corresponding_rrsig_filename)
    if len(dnskey_or_ds_rrset) == 0:
        print_answer_file(dnskey_or_ds_rrset_filename)
        raise DigsecError('no DNSKEY or DS RR in the %s file' %
                          dnskey_or_ds_rrset_filename)
    rrset = list(map(lambda x: x.l2(), an_rrset))
    # this is already checked above, there is definitely one element
    rrsig = corresponding_rrsig_rrset[0].l2()
    dnskey_or_ds_rrset = list(map(lambda x: x.l2(), dnskey_or_ds_rrset))
    validate(rrset, rrsig, dnskey_or_ds_rrset)
