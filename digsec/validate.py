# coding: utf-8
# pylint: disable=invalid-name
"""
handles validate command
"""
import binascii
import sys
from datetime import datetime
from digsec import dprint, error, ensure_file_exists
from digsec.algorithms import dnssec_algorithms, dnssec_digests
from digsec.help import display_help_validate
from digsec.utils import parse_flags, get_dnskeys
from digsec.answer import print_answer_file, read_answer_file


def validate_rrsig(rrset,
                   rrsig,
                   dnskey_rrset):
    """
    Validate rrsig of rrset with dnskey_rrset.

    If rrset contains DNSKEY records, rrset equals to dnskey_rrset.

    Arguments:
        rrset -- any rrset
        rrsig -- RRSIG of rrset
        dnskey_rrset -- DNSKEY rrset containing the ZSK

    Returns:
        (True, dnskey) -- if rrsig can be validated with any dnskey
        (False, None) -- if rrsig cannot be validated
    """

    # finds our algo function
    # raises Error if algo is not supported
    verification_algorithm = dnssec_algorithms.get(rrsig.algorithm)

    # finds corresponding ZSK DNSKEY with same keytag, algo and name
    # raises Error if no DNSKEY can be found
    dnskeys = get_dnskeys(dnskey_rrset,
                          rrsig.keytag,
                          rrsig.algorithm,
                          rrsig.signers_name)

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

    # if multiple dnskeys match the requirements, each should be tried
    for dnskey in dnskeys:
        dprint('Using DNSKEY name: %s, keytag: %d, algorithm: %s' %
               (dnskey.name, dnskey.keytag, dnskey.algorithm))

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
        dnskey --
        ds --

    Returns:
        True -- if ds contains a valid digest of dnskey
        False -- if not
    """

    if not dnskey.zone_key:
        error(('DNSKEY keytag %d, algorithm %s is ' +
               'not marked as Zone Key (bit 7)') % (dnskey.keytag,
                                                    dnskey.algorithm))

    verification_algorithm = dnssec_digests[ds.digest_type]
    if verification_algorithm is None:
        error('digsec does not support digest: %s yet' %
              ds.digest_type)

    dprint('Hashed Data (DNSKEY NAME + DNSKEY RDATA): 0x%s' %
           binascii.hexlify(dnskey.digest_data).decode('ascii'))

    verified = verification_algorithm(dnskey.digest_data, ds.digest)

    return verified


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
        error('Missing arguments, see usage')
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
    corresponding_rrsig = read_answer_file(corresponding_rrsig_filename)
    dnskey_or_ds_rrset = read_answer_file(dnskey_or_ds_rrset_filename)
    if flags['show-file-contents']:
        print_answer_file(an_rrset_filename)
        print_answer_file(corresponding_rrsig_filename)
        print_answer_file(dnskey_or_ds_rrset_filename)
    if len(an_rrset) == 0:
        print_answer_file(an_rrset_filename)
        error('no RR in the %s file' % an_rrset_filename)
    if len(corresponding_rrsig) == 0:
        print_answer_file(corresponding_rrsig_filename)
        error('no RRSIG in the %s file' % corresponding_rrsig_filename)
    if len(dnskey_or_ds_rrset) == 0:
        print_answer_file(dnskey_or_ds_rrset_filename)
        error('no DNSKEY or DS in the %s file' % dnskey_or_ds_rrset_filename)
    rrset = list(map(lambda x: x.l2(), an_rrset))
    an_rr = rrset[0]
    now = datetime.now()
    for one_corresponding_rrsig in corresponding_rrsig:
        rrsig = one_corresponding_rrsig.l2()
        for rr in rrset:
            if rr.name != an_rr.name:
                print_answer_file(an_rrset_filename)
                error('multiple names exist in %s' % an_rrset_filename)
            if rr.typ != an_rr.typ:
                print_answer_file(an_rrset_filename)
                error('multiple types exists in %s' % an_rrset_filename)
            if rr.clas != an_rr.clas:
                print_answer_file(an_rrset_filename)
                error('multiple classes exist in %s' % an_rrset_filename)
            if rr.name != rrsig.name:
                print_answer_file(an_rrset_filename)
                print_answer_file(corresponding_rrsig_filename)
                error('RR.name: %s is different than RRSIG.name: %s' %
                      (rr.name, rrsig.name))
            if rr.typ != rrsig.type_covered:
                print_answer_file(an_rrset_filename)
                print_answer_file(corresponding_rrsig_filename)
                error('RRSIG does not cover RR type %s but %s' % (rr.typ,
                                                                  rrsig.typ))
            if rr.clas != rrsig.clas:
                print_answer_file(an_rrset_filename)
                print_answer_file(corresponding_rrsig_filename)
                error('RR.class: %s is different than RRSIG.class: %s' %
                      (rr.clas, rrsig.clas))
            # len control is for root
            if len(rr.name) > 0:
                # -1 is because root has empty label and split('.') produces
                # this empty label as well
                # e.g. labels is 0 for root(.), 1 for com, 2 for metebalci.com
                if (len(rr.name.split('.'))-1) != rrsig.labels:
                    print_answer_file(an_rrset_filename)
                    print_answer_file(corresponding_rrsig_filename)
                    error('RR.name has different number of labels than ' +
                          'RRSIG.labels')

        if now < rrsig.signature_inception:
            error('RRSIG is not valid yet (now < signature inception)')

        if now > rrsig.signature_expiration:
            error('RRSIG is not valid anymore (now > signature expiration)')

        if rrsig.type_covered == 'DNSKEY':
            ds_rrset = []
            for ds_rr in dnskey_or_ds_rrset:
                ds_rr = ds_rr.l2()
                if ds_rr.typ != 'DS':
                    error(('RRSIG covers DNSKEY but DS is not provided, ' +
                           'but %s' % ds_rr.typ))
                ds_rrset.append(ds_rr)
            # also set dnskey_rrset because it also going to be used
            # by first validate_rrsig just below
            dnskey_rrset = rrset
        else:
            dnskey_rrset = []
            for dnskey_rr in dnskey_or_ds_rrset:
                dnskey_rr = dnskey_rr.l2()
                if dnskey_rr.typ != 'DNSKEY':
                    error(('RRSIG covers %s but DNSKEY is not provided, ' +
                           'but %s') % (rrsig.type_covered, dnskey_rr.typ))
                dnskey_rrset.append(dnskey_rr)

        # all RRSIG is signed with DNSKEY, also RRSIG.DNSKEY
        # but when it is RRSIG.DNSKEY, the digest of DNSKEY
        # also has to be checked against the DS
        valid, dnskey_signed_rrsig = validate_rrsig(
            rrset,
            rrsig,
            dnskey_rrset)
        if valid:
            print('OK: SIGNATURE VALID: RRSIG(%s,%s) with DNSKEY(%d,%s)' %
                    (rrsig.type_covered,
                    rrsig.algorithm,
                    dnskey_signed_rrsig.keytag,
                    dnskey_signed_rrsig.algorithm))
        else:
            print('NOK: SIGNATURE INVALID: RRSIG(%s,%s) with DNSKEY(%d,%s)' %
                    (rrsig.type_covered,
                    rrsig.algorithm,
                    dnskey_signed_rrsig.keytag,
                    dnskey_signed_rrsig.algorithm))
            sys.exit(1)


        if rrsig.type_covered == 'DNSKEY':

            # checking the dnskey signed RRSIG is same as the one
            # having the digest in DS
            dprint(ds_rrset)
            def sorting_lambda(keytag):
                return lambda x: x.keytag == keytag
            selected_ds_list = list(
                filter(
                    sorting_lambda(dnskey_signed_rrsig.keytag),
                    ds_rrset))
            if len(selected_ds_list) == 0:
                print('WARNING: no DS for DNSKEY with keytag: %d' %
                        dnskey_signed_rrsig.keytag)
                continue
            if len(selected_ds_list) > 1:
                error('multiple DS with keytag: %d' %
                        dnskey_signed_rrsig.keytag)

            ds = selected_ds_list[0]

            valid = validate_dnskey(dnskey_signed_rrsig,
                                    ds)
            if valid:
                print('OK: DIGEST VALID: DNSKEY(%d,%s) with DS(%s)' % (
                    ds.keytag,
                    ds.algorithm,
                    ds.digest_type))
            else:
                print('NOK: DIGEST INVALID: DNSKEY(%d,%s) with DS (%s)' % (
                    ds.keytag,
                    ds.algorithm,
                    ds.digest_type))
                sys.exit(1)
