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
    - download: download and save official trust anchors (from IANA)
    - validate: validate DNSSEC records saved by query

    Potential use cases:
    - Save DNS query/response packets
    - Display DNS protocol messages and their friendly interpretation
    - Run and observe DNSSEC validation process

    Recommendation for first use:
    - run download to save DS trust anchors
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
    digsec query <qname> [<qtype>] [<qclass>] <flags>

    Use dot "." as qname to query for root domain.

    FLAGS are:
          +[no]rd: set/reset Recursive Desired flag
          +[no]cd: set/reset Checking Disabled flag
          +[no]do: set/reset DNSSEC OK bit in EDNS
          +udp_payload_size=<size>: set UDP payload size (in octets) in EDNS
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
          [+save-root-anchors=[<filename>]]: save downloaded root anchor file
          [+save-ds-anchors=[<filename>]]: save trust anchor for validate
          +help: show this help
          +debug: enable debug mode

    Default FLAGS are:
          (none)

    Notes:
        Default filename for +save-root-anchors is root-anchors.xml
        Default filename for +save-ds-anchors is _root.IN.DS
        root anchor file is https://data.iana.org/root-anchors/root-anchors.xml
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
