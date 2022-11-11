#!/usr/bin/env python
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
A script for fully authenticating DNS response with digsec.
This requires multiple queries and validations.

based on RFC 4035, Section 5: Authenticating DNS Responses

This is not working yet for 2+ level domains (e.g. www.metebalci.com).
"""
import os
import sys


def print_help():
    sys.exit(1)


def query_cmd(server, q, rr, dest):
    return 'digsec query @%s %s %s +rd +cd +do +udp_payload_size=2048 ' \
        '+save-answer +save-answer-dir=%s' % (server, q, rr, dest)


def validate_cmd(dest, rrset, rrsig, dnskey_or_ds):
    return 'digsec validate %s %s %s' % (os.path.join(dest, rrset),
                                         os.path.join(dest, rrsig),
                                         os.path.join(dest, dnskey_or_ds))


def run(cmd):
    ret = os.system(cmd)
    if ret != 0:
        sys.exit(1)


# pylint: disable=too-many-statements
def main():
    rr = 'A'
    dest = '/tmp'
    server = '8.8.8.8'
    if len(sys.argv) >= 2:
        q = sys.argv[1]
    if len(sys.argv) >= 3:
        rr = sys.argv[2]
    if len(sys.argv) >= 4:
        dest = sys.argv[3]
    if len(sys.argv) >= 5 or len(sys.argv) <= 1:
        print_help()
    qparts = q.split('.')

    print('--- querying ---')

    print('saving _root.DS (trust anchor)')
    current_cmd = 'digsec download +save-ds-anchors=%s' % (
        os.path.join(dest, '_root.IN.'))
    print(current_cmd)
    run(current_cmd)

    print('saving _root.DNSKEY')
    current_cmd = query_cmd(server, '.', 'DNSKEY', dest)
    print(current_cmd)
    run(current_cmd)

    if q != '.':

        for i in range(len(qparts) - 1, -1, -1):

            current_domain = '.'.join(qparts[i:])

            print('saving %s.DS' % current_domain)
            current_cmd = query_cmd(server, current_domain, 'DS', dest)
            print(current_cmd)
            run(current_cmd)

            print('saving %s.DNSKEY' % current_domain)
            current_cmd = query_cmd(server, current_domain, 'DNSKEY', dest)
            print(current_cmd)
            run(current_cmd)

            # DNSKEY is already saved above
            if i == 0 and rr != 'DNSKEY':
                print('saving %s.%s' % (current_domain, rr))
                current_cmd = query_cmd(server, current_domain, rr, dest)
                print(current_cmd)
                run(current_cmd)

    print('--- validating ---')

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
