#!/usr/bin/env python
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
A script for recursively resolve a query with digsec.
It saves all responses to destination folder.
This requires multiple queries.
based on RFC 4035, Section 4: Resolving
"""
import os
import sys


def print_help():
    print('Usage: resolve.py <domain> <rr> <dest_folder> <server>')
    sys.exit(1)


def query_cmd(server, q, rr, dest):
    return 'digsec query @%s %s %s +rd +cd +do +udp_payload_size=2048 ' \
        '+show-friendly +save-answer +save-answer-dir=%s' % (server,
                                                             q,
                                                             rr,
                                                             dest)


def run(cmd):
    ret = os.system(cmd)
    if ret != 0:
        sys.exit(1)


# pylint: disable=too-many-statements
def main():
    rr = 'A'
    dest = '/tmp'
    server = '1.1.1.1'
    if len(sys.argv) >= 2:
        q = sys.argv[1]
    if len(sys.argv) >= 3:
        rr = sys.argv[2]
    if len(sys.argv) >= 4:
        dest = sys.argv[3]
    if len(sys.argv) >= 5:
        server = sys.argv[4]
    if len(sys.argv) >= 6 or len(sys.argv) <= 1:
        print_help()
    qparts = q.split('.')

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

if __name__ == "__main__":
    main()
