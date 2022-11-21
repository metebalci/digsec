# digsec

[![CircleCI](https://circleci.com/gh/metebalci/digsec/tree/master.svg?style=svg)](https://circleci.com/gh/metebalci/digsec/tree/master)

`digsec` is a standalone command line tool to be used for self-learning, teaching or troubleshooting DNSSEC. 

It is primarily a raw DNS tool, that does not implicitly add any DNS flags, or automatically perform multi-step operations like authenticating a DNSSEC record.

Technically, `digsec` is similar to a validating, DNSSEC-aware resolver. However, it either does query (in other words lookup) or validate (in other words authenticate) at each run. With `digsec query`, only a single DNS lookup is performed (e.g. lookup a DNSKEY record of a domain). With `digsec validate`, only a single validation is performed (e.g. validate an A record with a DNSKEY record). Typically, for a normal DNSSEC validating query, `digsec` would have to be executed multiple times. `digsec query` naturally requires network communication (with a DNS server), whereas `validate` runs off-line. To be able to run validation, the answers to queries can be saved to temporary files. 

As an example, `digsec.resolve` and `digsec.authenticate` is provided to perform multi-step operations. `digsec.resolve` (iteratively) resolves and saves all responses to a query. `digsec.authenticate` validates a query by performing multiple validations using the saved responses. These tools are provided only as an example, not as production-quality utilities.

DNSSEC Trust Anchors can be downloaded with `digsec`, and if required their validation can be done using openssl. `digsec.authenticate` does the validation using `openssl`.

`digsec` is not supposed to be embedded into another code e.g. it is not a library. There is no proper error reporting (all errors are raised as exception and catched to give a single error message to user), and no machine-friendly return values. I do not plan to change this.

# Install

`pip install digsec`

# Usage

Just run digsec to see options, flags and help, or much better see [my blog post](https://metebalci.com/blog/a-minimum-complete-tutorial-of-dnssec/) explaining how it is used with DNSSEC.

As a simple example, you can try:

```
$ digsec.resolve metebalci.com DNSKEY /tmp 1.1.1.1
...
$ digsec.authenticate metebalci.com DNSKEY /tmp
...
```

`digsec.resolve` command above will query metebalci.com DNSKEY and all other required records for authenticating this record. All these DNS queries will be send to 1.1.1.1. It will save the responses to these queries under `/tmp`. Then `digsec.authenticate` command will try to authenticate metebalci.com DNSKEY using the save responses under `/tmp`. These commands should work without any error.

In case of any error, `digsec`:

- returns a non-zero exit code
- prints a message starting with `ERROR:` describing the error  

`digsec.resolve` and `digsec.authenticate` follows a similar eror reporting but it is not extensively tested.

# Supported Records, Algorithms and Digests

These record types are supported in query: SOA, NS, A, AAAA, MX, TXT, DNSKEY, RRSIG, DS, NSEC, NSEC3.

Negative authentication is not supported yet, so NSEC and NSEC3 is not supported for validation, but it will be added.

These algorithms are supported:

- 5: RSASHA1
- 7: RSASHA1-NSEC3-SHA1 (alias for 5)
- 8: RSASHA256
- 10: RSASHA512
- 13: ECDSAP256SHA256
- 14: ECDSAP384SHA384
- 15: ED25519
- 16: ED448

These are all algorithms that are required or recommended for DNSSEC validation per RFC 8624.

There is no plan to support deprecated or vulnerable RSAMD5 (1), DSA (3), DSA-NSEC3-SHA1 (6) and optional ECC-GOST (12).

These digests are supported: 

- 1: SHA1
- 2: SHA256
- 4: SHA384

These are all digests that are required or recommended for DNSSEC validation per RFC 8624. 

There is no plan to support optional GOST R 34.11.94 (3) digest.

# Hints

- digsec do not add DNS flags implicitly. You might need to use +rd (recursive desired) often. Also, if you are looking to invalid DNSSEC records, you might need to use +cd (checking disabled) flag, otherwise the DNS server may not return them.

# Release History

0.9: 
  - AAAA record type support
  - Ed25519 and Ed448 support
  - view command
  - changed default DNS of query and scripts/validate.py to Cloudflare 1.1.1.1
  - fixed name, it was shown without root (metebalci.com instead of metebalci.com.) 
  - test resolve and authenticate methods resolve.py and authenticate.py,
    they can be called by digsec.resolve and digsec.authenticate
  - major changes in error handling and some code reorganization
  - EDNS0 opt reporing improved
  - Extended DNS Errors (Code 15) support

0.8.1:
  - digsec download outputs signature and CA file for trust anchor verification
  - digsec download can use a local root anchors XML file rather than downloading it

0.8:
  - pylint added to build process, but only important and easy to fix errors are fixed.
  - default timeout value of 1s is removed. now it defaults to system default. if needed, it can be set with +timeout=X_in_seconds_float flag.
  - tcp support with +tcp flag, default is udp
  - non-53 port support with @server_ip:server_port, default is 53
  - validate script is replaced with new scripts/validate.py
  - rsa dependency updated to 4.9, ecdsa dependency updated to 0.18.0

0.7.1:
  - rsa update in 0.7 broke the build, this version fixes the issue.

0.7:
  - required packages (rsa and ecdsa) are updated to latest version

0.6:
  - Socket timeout support and +timeout flag.

0.5:
  - Preliminary support for ECDSAP384SHA384, RSA-512, SHA-384.
  - Server the DNS packet is sent is written under NETWORK COMMUNICATION line.
  - digsec version is written at first line in the output as digsec vX.

0.4: 
  - ECDSAP256SHA256 implemented. 
  - @server option added. 
  - validate_second_level_domain.sh script added.
