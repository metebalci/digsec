import sys
import binascii
from datetime import datetime
from digsec import dprint, error, ensure_file_exists
from digsec.algorithms import dnssec_algorithms, dnssec_digests
from digsec.help import display_help_validate
from digsec.utils import parse_flags
from digsec.answer import print_answer_file, read_answer_file


def validate_rrsig(corresponding_rrsig_filename,
                   dnskey_or_ds_rrset_filename,
                   rrset,
                   rrsig,
                   dnskey_rrset):

    verification_algorithm = dnssec_algorithms.get(rrsig.algorithm)

    if verification_algorithm is None:
        error('digsec does not support algorithm: %s yet' %
              rrsig.algorithm)

    dnskeys = list(filter(lambda x: x.keytag == rrsig.keytag,
                          dnskey_rrset))
    if len(dnskeys) == 0:
        print_answer_file(corresponding_rrsig_filename)
        print_answer_file(dnskey_or_ds_rrset_filename)
        error('No DNSKEY with keytag %d in %s' %
              (rrsig.keytag, dnskey_or_ds_rrset_filename))

    dnskeys = list(filter(lambda x: x.algorithm == rrsig.algorithm,
                          dnskeys))

    if len(dnskeys) == 0:
        print_answer_file(corresponding_rrsig_filename)
        print_answer_file(dnskey_or_ds_rrset_filename)
        error('No DNSKEY with keytag %d and algorithm %s' %
              (rrsig.keytag, rrsig.algorithm))

    dnskeys = list(filter(lambda x: x.name == rrsig.signers_name,
                          dnskeys))

    if len(dnskeys) == 0:
        print_answer_file(corresponding_rrsig_filename)
        print_answer_file(dnskey_or_ds_rrset_filename)
        error('No DNSKEY with keytag %d, algorithm %s and name %s' %
              (rrsig.keytag, rrsig.algorithm, rrsig.signers_name))

    dnskeys = list(filter(lambda x: x.zone_key, dnskeys))

    if len(dnskeys) == 0:
        print_answer_file(corresponding_rrsig_filename)
        print_answer_file(dnskey_or_ds_rrset_filename)
        error('No ZSK DNSKEY with keytag %d, algorithm %s and name %s' %
              (rrsig.keytag, rrsig.algorithm, rrsig.signers_name))

    canonical_rrset = map(lambda rr: rr.canonical_l1(rrsig.original_ttl),
                          rrset)

    canonical_rrset = sorted(canonical_rrset,
                             key=lambda x: binascii.hexlify(x.rdata))

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

        verified = verification_algorithm(signed_data,
                                          rrsig.signature,
                                          dnskey)
        if verified:
            return True, dnskey

    return False, None


def validate_dnskey(dnskey_filename, dnskey, ds):
    if not dnskey.zone_key:
        print_answer_file(dnskey_filename)
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


def do_validate(argv):
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
    any_of_dnskey_is_valid = False
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
                if len(rr.name.split('.')) != rrsig.labels:
                    print_answer_file(an_rrset_filename)
                    print_answer_file(corresponding_rrsig_filename)
                    error('RR.name has different number of labels than ' +
                          'RRSIG.labels')

        if now < rrsig.signature_inception:
            error('RRSIG is not valid yet')

        if now > rrsig.signature_expiration:
            error('RRSIG is not valid anymore')

        use_ds = False
        if rrsig.type_covered == 'DNSKEY':
            ds_rrset = []
            for ds_rr in dnskey_or_ds_rrset:
                ds_rr = ds_rr.l2()
                if ds_rr.typ != 'DS':
                    error(('RRSIG covers DNSKEY but DS is not provided, ' +
                           'but %s' % ds_rr.typ))
                ds_rrset.append(ds_rr)
            use_ds = True
        else:
            dnskey_rrset = []
            for dnskey_rr in dnskey_or_ds_rrset:
                dnskey_rr = dnskey_rr.l2()
                if dnskey_rr.typ != 'DNSKEY':
                    error(('RRSIG covers %s but DNSKEY is not provided, ' +
                           'but %s') % (rrsig.type_covered, dnskey_rr.typ))
                dnskey_rrset.append(dnskey_rr)

        if use_ds:
            dnskey_rrset = rrset

            valid, dnskey_signed_rrsig = validate_rrsig(
                corresponding_rrsig_filename,
                an_rrset_filename,
                dnskey_rrset,
                rrsig,
                dnskey_rrset)

            if valid:
                print('OK RRSIG (%s, %s) with DNSKEY (%d, %s)' %
                      (rrsig.type_covered,
                       rrsig.algorithm,
                       dnskey_signed_rrsig.keytag,
                       dnskey_signed_rrsig.algorithm))

                # checking the dnskey signed RRSIG is same as the one
                #  having the digest in DS
                dprint(ds_rrset)
                selected_ds_list = list(
                    filter(
                        lambda x: x.keytag == dnskey_signed_rrsig.keytag,
                        ds_rrset))
                if len(selected_ds_list) == 0:
                    print('WARNING: no DS for DNSKEY with keytag: %d' %
                          dnskey_signed_rrsig.keytag)
                    continue
                if len(selected_ds_list) > 1:
                    error('multiple DS with keytag: %d' %
                          dnskey_signed_rrsig.keytag)

                ds = selected_ds_list[0]

                valid = validate_dnskey(dnskey_or_ds_rrset_filename,
                                        dnskey_signed_rrsig,
                                        ds)
                if valid:
                    any_of_dnskey_is_valid = True
                    print('OK DNSKEY (%d, %s) with DS (%s)' % (ds.keytag,
                                                               ds.algorithm,
                                                               ds.digest_type))
                else:
                    print(('ERROR in DS (%s) DNSKEY (%d, %s) Validation ! ' +
                           'Digest Mismatch') %
                          (ds.digest_type, ds.keytag, ds.algorithm))
                    sys.exit(1)
            else:
                print('ERROR in RRSIG (%s, %s) Validation !' %
                      (rrsig.type_covered, rrsig.algorithm))
                sys.exit(1)

        else:
            valid, dnskey_signed_rrsig = validate_rrsig(
                corresponding_rrsig_filename,
                dnskey_or_ds_rrset_filename,
                rrset,
                rrsig,
                dnskey_rrset)

            if valid:
                print('OK RRSIG (%s, %s) with DNSKEY (%d, %s)' %
                      (rrsig.type_covered,
                       rrsig.algorithm,
                       dnskey_signed_rrsig.keytag,
                       dnskey_signed_rrsig.algorithm))
            else:
                print(('ERROR in RRSIG (%s, %s) Validation ! ' +
                       'Signature Mismatch') %
                      (rrsig.type_covered, rrsig.algorithm))
                sys.exit(1)
    if use_ds and not any_of_dnskey_is_valid:
        print('ERROR in RRSIG (%s, %s) Validation !' %
              (rrsig.type_covered, rrsig.algorithm))
        print('None of DNSKEYs could be validated with DS !')
        sys.exit(1)
