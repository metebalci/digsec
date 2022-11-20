#!/usr/bin/env python
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
A script for authenticating DNS responses with digsec.
This uses previously saved responses.
It requires openssl executable for authenticating the trust anchor.
based on RFC 4035, Section 5: Authenticating DNS Responses
"""
import os
import sys


def print_help():
    print('Usage: validate.py <domain> <rr> <dest_folder>')
    sys.exit(1)


def validate_cmd(dest, rrset, rrsig, dnskey_or_ds):
    return 'digsec validate %s %s %s' % (os.path.join(dest,
                                                      rrset),
                                         os.path.join(dest,
                                                      rrsig),
                                         os.path.join(dest,
                                                      dnskey_or_ds))


def run(cmd):
    ret = os.system(cmd)
    if ret != 0:
        sys.exit(1)


# pylint: disable=too-many-statements
def main():
    rr = 'A'
    dest = '/tmp'
    if len(sys.argv) >= 2:
        q = sys.argv[1]
    if len(sys.argv) >= 3:
        rr = sys.argv[2]
    if len(sys.argv) >= 4:
        dest = sys.argv[3]
    if len(sys.argv) >= 5 or len(sys.argv) <= 1:
        print_help()
    qparts = q.split('.')

    print('saving _root.DS (trust anchor)')
    current_cmd = 'digsec download +save-root-anchors=%s ' \
        '+save-ds-anchors=%s' % (os.path.join(dest, 'root-anchors.xml'),
                                 os.path.join(dest, '_root.IN'))
    print(current_cmd)
    run(current_cmd)

    print('validating trust anchor')
    current_cmd = 'openssl smime -verify -CAfile %s -inform der -in %s ' \
        '-content %s' % (os.path.join(dest, 'root-anchors.xml.ca'),
                         os.path.join(dest, 'root-anchors.xml.p7s'),
                         os.path.join(dest, 'root-anchors.xml'))
    print(current_cmd)
    run(current_cmd)

    print('validating _root.DNSKEY with _root.DS (trust anchor)')
    current_cmd = validate_cmd(dest,
                               '_root.IN.DNSKEY',
                               '_root.IN.RRSIG.DNSKEY',
                               '_root.IN.DS')
    print(current_cmd)
    run(current_cmd)

    if q != '.':

        higher_domain = '_root'

        for i in range(len(qparts) - 1, -1, -1):

            current_domain = '.'.join(qparts[i:])

            print('validating %s.DS with %s.DNSKEY' % (current_domain,
                                                       higher_domain))
            current_cmd = validate_cmd(dest,
                                       '%s.IN.DS' % current_domain,
                                       '%s.IN.RRSIG.DS' % current_domain,
                                       '%s.IN.DNSKEY' % higher_domain)
            print(current_cmd)
            run(current_cmd)

            print('validating %s.DNSKEY with %s.DS' % (current_domain,
                                                       current_domain))
            current_cmd = validate_cmd(dest,
                                       '%s.IN.DNSKEY' % current_domain,
                                       '%s.IN.RRSIG.DNSKEY' % current_domain,
                                       '%s.IN.DS' % current_domain)
            print(current_cmd)
            run(current_cmd)

            # DNSKEY is already authenticated above
            # you cannot authenticate DNSKEY with itself
            if i == 0 and rr != 'DNSKEY':
                print('validating %s.%s with %s.DNSKEY' % (current_domain,
                                                           rr,
                                                           current_domain))
                current_cmd = validate_cmd(dest,
                                           '%s.IN.%s' % (current_domain, rr),
                                           '%s.IN.RRSIG.%s' % (current_domain,
                                                               rr),
                                           '%s.IN.DNSKEY' % current_domain)
                print(current_cmd)
                run(current_cmd)

            higher_domain = current_domain


if __name__ == "__main__":
    main()
