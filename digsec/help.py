# coding: utf-8
# pylint: disable=missing-function-docstring
"""
displays help
"""
import sys


def display_help_header():
    print('''
    digsec is a tool to understand how DNSSEC works.''')


def display_help():
    display_help_header()
    print('''
    digsec <command> <flags>

    command can be:
    - query: perform a DNSSEC query
    - download: download and save trust anchors (from IANA) (DEPRECATED)
    - root-anchors: download or use trust anchors XML and generate DS RRset
    - validate: validate DNSSEC records saved by query

    Potential use cases:
    - Save DNS query/response packets
    - Display DNS protocol messages and their friendly interpretation
    - Run and observe DNSSEC validation process

    Recommendation for first use:
    - (optional) use DNSSEC Trust Anchor Fetcher to download DNSSEC trust anchor
    - run root-anchors to save DS trust anchors
    - run query for any domain you want (e.g. www.metebalci.com)
    - run validate when you want, but you need to run query first for
      parent domains for a proper authentication chain
      (e.g. metebalci.com. , com. , .)

    Help:
    Use +help flag with a command to learn more.

    Debugging:
    +debug flag can be used with all commands, but it is not intended for
     general use.
    ''')
    sys.exit(1)


def display_help_query():
    display_help_header()
    print('''
    digsec query [@server] <qname> [<qtype>] [<qclass>] <flags>

    Use dot "." as qname to query for root domain.

    FLAGS are:
          +[no]rd: set/reset Recursive Desired flag
          +[no]cd: set/reset Checking Disabled flag
          +[no]do: set/reset DNSSEC OK bit in EDNS
          +udp_payload_size=<size>: set UDP payload size (in octets) in EDNS
          +timeout=<timeout>: set socket timeout in seconds (float), default is 1 seconds
          +tcp: use tcp instead of udp, default is udp
          +[no]show-friendly: show query and response in friendly format
          +[no]show-protocol: show query and response in protocol format
          +save-answer: save the answer
          +save-answer-prefix=<prefix>: save file with prefix
          +save-answer-dir=<path>: save file to path
          +save-packets=filename: save query and response to filename.q and .r
          +help: show this help
          +debug: enable debug mode

    Default FLAGS are:
          if +save-answer is not specified, +show-friendly is implied.
          if server is not specified, Cloudflare Public DNS 1.1.1.1 is used at port 53.

    non-53 ports:
          @server can be given with a port number e.g. @a.b.c.d:53

    Notes:
    - +do requires +udp_payload_size=<size>
    - Filename for +save-answer is:
        - For non-RRSIG answers: [prefix]qname.qclass.qtype
        - For RRSIG answers: [prefix]qname.qclass.qtype.RRSIG_type_covered
          because there is a different RRSIG for each type
        - If prefix is not specified, it is empty string
        - If dir is not specified, it is current working directory
    - For filenames, "_root" is used if qname is dot "."

    Why udp_payload_size is a must ?
    - UDP payload size cannot be removed, because it has to be in EDNS
      and EDNS is a must for DNSSEC.
    ''')
    sys.exit(1)


def display_help_download():
    display_help_header()
    print('''
    digsec download <flags>

    FLAGS are:
          [+save-root-anchors=[<filename>]]: save downloaded DNSSEC trust anchors (XML) file
          [+root-anchors-location=[url-or-filepath]]: http/https or filepath of DNSSEC trust anchors
          [+save-ds-anchors=[<filename_prefix>]]: save trust anchor for validate
          +help: show this help
          +debug: enable debug mode

    Default FLAGS are:
          +root-anchors-location=https://data.iana.org/root-anchors

    Notes:
        Default filename for +save-root-anchors is root-anchors.xml
        Default filename prefix for +save-ds-anchors is _root.IN
        +save-ds-anchors implicitly appends .DS suffix
        +root-anchors-location can be set to a remote http/https location or local filepath
        If http/https is given as root-anchors-location:
         - the remote root-anchors file should be called root-anchors.xml
         - the remote signature file should be called root-anchors.p7s
        If local filepath is given as root-anchors-location, it should point to a root anchors XML file.
        If +save-root-anchors is specified and +root-anchors-location is http/https URL,
          in addition to root-anchors:
          - detached CMS signature (also downloaded) of root-anchors XML file (root-anchors.p7s)
          - ICANN CA file (embedded in the code) the signature is chained to
          is also saved as <root-anchors-filename>.p7s and <root-anchors-filename>.ca. These two files:
          can be used to verify root-anchors XML file (RFC 7958) with openssl:
          openssl smime -verify -CAfile root-anchors.xml.ca -inform der -in root-anchors.xml.p7s -content root-anchors.xml
          This verification is not done by digsec, it should be done externally.
    ''')
    sys.exit(1)


def display_help_validate():
    display_help_header()
    print('''
    digsec validate an.rrset corresponding.rrsig dnskey_or_ds.rrset <flags>

    If an.rrset is any other RRset than DNSKEY, dnskey.rrset is needed.
    If an.rrset is a DNSKEY rrset, ds.rrset is needed.

    an.rrset and corresponding.rrsig is saved using
        digsec query with +save-answer flag

    dnskey_or_ds.rrset is saved either using
        digsec query with +save-answer flag OR
        digsec download with +save-answer flag for DS trust anchors

    FLAGS are:
          +help: show this help
          +debug: enable debug mode
          +print-files: before validation print the contents of files

    Default FLAGS are:
          (none)
    ''')
    sys.exit(1)


def display_help_view():
    display_help_header()
    print('''
    digsec view an.rrset <flags>

    FLAGS are:
          +help: show this help
          +debug: enable debug mode

    Default FLAGS are:
          (none)
    ''')
    sys.exit(1)
