# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
constants used in the project
"""
# make a dictionary[k, v] from dictionary[v, k]
def reverse_dict(d):
    rd = {}
    for k, v in d.items():
        rd[v] = k
    return rd


# this is not an exhaustive list
# source: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
DNS_CLASS_TO_INT = {}
DNS_CLASS_TO_INT['IN'] = 1
DNS_CLASS_TO_INT['ANY'] = 255
DNS_CLASS_TO_STR = reverse_dict(DNS_CLASS_TO_INT)


# this is not an exhaustive list
# source: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
DNS_TYPE_TO_INT = {}
DNS_TYPE_TO_INT['A'] = 1
DNS_TYPE_TO_INT['NS'] = 2
DNS_TYPE_TO_INT['CNAME'] = 5
DNS_TYPE_TO_INT['SOA'] = 6
DNS_TYPE_TO_INT['PTR'] = 12
DNS_TYPE_TO_INT['HINFO'] = 13
DNS_TYPE_TO_INT['MX'] = 15
DNS_TYPE_TO_INT['TXT'] = 16
DNS_TYPE_TO_INT['AAAA'] = 28
DNS_TYPE_TO_INT['LOC'] = 29
DNS_TYPE_TO_INT['SRV'] = 33
DNS_TYPE_TO_INT['NAPTR'] = 35
DNS_TYPE_TO_INT['CERT'] = 37
DNS_TYPE_TO_INT['OPT'] = 41
DNS_TYPE_TO_INT['DS'] = 43
DNS_TYPE_TO_INT['SSHFP'] = 44
DNS_TYPE_TO_INT['RRSIG'] = 46
DNS_TYPE_TO_INT['NSEC'] = 47
DNS_TYPE_TO_INT['DNSKEY'] = 48
DNS_TYPE_TO_INT['NSEC3'] = 50
DNS_TYPE_TO_INT['TLSA'] = 52
DNS_TYPE_TO_INT['SMIMEA'] = 53
DNS_TYPE_TO_INT['HIP'] = 55
DNS_TYPE_TO_INT['OPENPGPKEY'] = 61
DNS_TYPE_TO_INT['ANY'] = 255
DNS_TYPE_TO_INT['URI'] = 256
DNS_TYPE_TO_INT['CAA'] = 257
DNS_TYPE_TO_STR = reverse_dict(DNS_TYPE_TO_INT)


# DNS OpCodes
# source: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
DNS_OPCODE_TO_INT = {}
DNS_OPCODE_TO_INT['Query'] = 0
DNS_OPCODE_TO_INT['IQuery'] = 1
DNS_OPCODE_TO_INT['Status'] = 2
DNS_OPCODE_TO_INT['Notify'] = 4
DNS_OPCODE_TO_INT['Update'] = 5
DNS_OPCODE_TO_STR = reverse_dict(DNS_OPCODE_TO_INT)


# DNS RCODEs
# source: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
DNS_RCODE_TO_INT = {}
DNS_RCODE_TO_INT['NoError'] = 0
DNS_RCODE_TO_INT['FormErr'] = 1
DNS_RCODE_TO_INT['ServFail'] = 2
DNS_RCODE_TO_INT['NXDomain'] = 3
DNS_RCODE_TO_INT['NotImp'] = 4
DNS_RCODE_TO_INT['Refused'] = 5
DNS_RCODE_TO_INT['YXDomain'] = 6
DNS_RCODE_TO_INT['YXRRSet'] = 7
DNS_RCODE_TO_INT['NXRRSet'] = 8
DNS_RCODE_TO_INT['NotAuth'] = 9
DNS_RCODE_TO_INT['NotZone'] = 10
DNS_RCODE_TO_INT['BADVERS|BADSIG'] = 16
DNS_RCODE_TO_INT['BADKEY'] = 17
DNS_RCODE_TO_INT['BADTIME'] = 18
DNS_RCODE_TO_INT['BADMODE'] = 19
DNS_RCODE_TO_INT['BADNAME'] = 20
DNS_RCODE_TO_INT['BADALG'] = 21
DNS_RCODE_TO_INT['BADTRUNC'] = 22
DNS_RCODE_TO_INT['BADCOOKIE'] = 23
DNS_RCODE_TO_STR = reverse_dict(DNS_RCODE_TO_INT)


# DNSSEC Algorithm Numbers and Mnemonics
# source: https://www.iana.org/assignments/dns-sec-alg-numbers/
# dns-sec-alg-numbers.xhtml
DNSSEC_ALGORITHM_TO_INT = {}
DNSSEC_ALGORITHM_TO_INT['RSAMD5'] = 1
DNSSEC_ALGORITHM_TO_INT['DH'] = 2
DNSSEC_ALGORITHM_TO_INT['DSA'] = 3
DNSSEC_ALGORITHM_TO_INT['RSASHA1'] = 5
DNSSEC_ALGORITHM_TO_INT['DSA-NSEC3-SHA1'] = 6
DNSSEC_ALGORITHM_TO_INT['RSASHA1-NSEC3-SHA1'] = 7
DNSSEC_ALGORITHM_TO_INT['RSASHA256'] = 8
DNSSEC_ALGORITHM_TO_INT['RSASHA512'] = 10
DNSSEC_ALGORITHM_TO_INT['ECC-GOST'] = 12
DNSSEC_ALGORITHM_TO_INT['ECDSAP256SHA256'] = 13
DNSSEC_ALGORITHM_TO_INT['ECDSAP384SHA384'] = 14
DNSSEC_ALGORITHM_TO_INT['ED25519'] = 15
DNSSEC_ALGORITHM_TO_INT['ED448'] = 16
DNSSEC_ALGORITHM_TO_STR = reverse_dict(DNSSEC_ALGORITHM_TO_INT)


DNSSEC_DIGEST_TYPE_TO_INT = {}
DNSSEC_DIGEST_TYPE_TO_INT['SHA-1'] = 1
DNSSEC_DIGEST_TYPE_TO_INT['SHA-256'] = 2
DNSSEC_DIGEST_TYPE_TO_INT['GOST R 34.11.94'] = 3
DNSSEC_DIGEST_TYPE_TO_INT['SHA-384'] = 4
DNSSEC_DIGEST_TYPE_TO_STR = reverse_dict(DNSSEC_DIGEST_TYPE_TO_INT)


# https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
DNSSEC_NSEC3_ALGORITHM_TO_INT = {}
DNSSEC_NSEC3_ALGORITHM_TO_INT['SHA-1'] = 1
DNSSEC_NSEC3_ALGORITHM_TO_STR = reverse_dict(DNSSEC_NSEC3_ALGORITHM_TO_INT)

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
EDNS0_OPT_CODES = {}
EDNS0_OPT_CODES['LLQ'] = 1
EDNS0_OPT_CODES['UL'] = 2
EDNS0_OPT_CODES['NSID'] = 3
EDNS0_OPT_CODES['DAU'] = 5
EDNS0_OPT_CODES['DHU'] = 6
EDNS0_OPT_CODES['N3U'] = 7
EDNS0_OPT_CODES['edns-client-subnet'] = 8
EDNS0_OPT_CODES['EDNS-EXPIRE'] = 9
EDNS0_OPT_CODES['COOKIE'] = 10
EDNS0_OPT_CODES['edns-tcp-keepalive'] = 11
EDNS0_OPT_CODES['Padding'] = 12
EDNS0_OPT_CODES['CHAIN'] = 13
EDNS0_OPT_CODES['edns-key-tag'] = 14
EDNS0_OPT_CODES['Extended DNS Error'] = 15
EDNS0_OPT_CODES['EDNS-Client-Tag'] = 16
EDNS0_OPT_CODES['EDNS-Server-Tag'] = 17
EDNS0_OPT_CODES['Umbrella Ident'] = 20292
EDNS0_OPT_CODES['DeviceID'] = 26946
EDNS0_OPT_CODES_TO_STR = reverse_dict(EDNS0_OPT_CODES)

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes
EDNS_ERR_CODES = {}
EDNS_ERR_CODES['Unsupported DNSKEY Algorithm'] = 1
EDNS_ERR_CODES['Unsupported DS Digest Type'] = 2
EDNS_ERR_CODES['Stale Answer'] = 3
EDNS_ERR_CODES['Forged Answer'] = 4
EDNS_ERR_CODES['DNSSEC Indeterminate'] = 5
EDNS_ERR_CODES['DNSSEC Bogus'] = 6
EDNS_ERR_CODES['Signature Expired'] = 7
EDNS_ERR_CODES['Signature Not Yet Valid'] = 8
EDNS_ERR_CODES['DNSKEY Missing'] = 9
EDNS_ERR_CODES['RRSIGs Missing'] = 10
EDNS_ERR_CODES['No Zone Key Bit Set'] = 11
EDNS_ERR_CODES['NSEC Missing'] = 12
EDNS_ERR_CODES['Cached Error'] = 13
EDNS_ERR_CODES['Not Ready'] = 14
EDNS_ERR_CODES['Blocked'] = 15
EDNS_ERR_CODES['Censored'] = 16
EDNS_ERR_CODES['Filtered'] = 17
EDNS_ERR_CODES['Prohibited'] = 18
EDNS_ERR_CODES['Stale NXDomain Answer'] = 19
EDNS_ERR_CODES['Not Authoritative'] = 20
EDNS_ERR_CODES['Not Supported'] = 21
EDNS_ERR_CODES['No Reachable Authority'] = 22
EDNS_ERR_CODES['Network Error'] = 23
EDNS_ERR_CODES['Invalid Data'] = 24
EDNS_ERR_CODES['Signature Expired before Valid'] = 25
EDNS_ERR_CODES['Too Early'] = 26
EDNS_ERR_CODES['Unsupported NSEC3 Iterations Value'] = 27
EDNS_ERR_CODES_TO_STR = reverse_dict(EDNS_ERR_CODES)
