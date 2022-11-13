# digsec

[![CircleCI](https://circleci.com/gh/metebalci/digsec/tree/master.svg?style=svg)](https://circleci.com/gh/metebalci/digsec/tree/master)

`digsec` is a standalone command line tool to be used for self-learning, teaching or troubleshooting DNSSEC. 

It is a raw DNS tool, that does not implicitly add any DNS flags, or automatically perform multi-step operations like authenticating a DNSSEC record.

Technically, `digsec` is a validating, DNSSEC-aware resolver. However, it either does query (in other words lookup) or validate (in other words authenticate) at each run. With `query`, only a single DNS lookup is performed (e.g. lookup a DNSKEY record of a domain). With `validate`, only a single validation is performed (e.g. validate an A record with a DNSKEY record). Typically, for a DNSSEC validating query, `digsec` would have to be executed multiple times. `query` run naturally requires network communication, whereas `validate` run is off-line. To be able to run validation, the answers to queries can be saved to temporary files.

DNSSEC Trust Anchors can be downloaded with `digsec`, and if required their validation can be done using openssl.

# For Developers

`digsec` is not supposed to be embedded into another code e.g. it is not a library. At the moment, I do not plan to convert it to a library, so if you are trying to embed it to another code, I might not be able to help due to various needs that might arise.

This is also true if it is used in a (bash) script. It might not be particularly script friendly, and I do not at the moment plan to make it as such. The script(s) under `scripts` folder is only meant to be used as indicated, they are not standalone tools. Basically, if you want to use `digsec` for a certain task, you have to write your own script using the `digsec` tool directly not the scripts.

# Install

`pip install digsec`

# Usage

Just run digsec to see options, flags and help, or much better see [my blog post](https://metebalci.com/blog/a-minimum-complete-tutorial-of-dnssec/) explaining how it is used with DNSSEC.

# Hints

- digsec do not add DNS flags implicitly. You might need to use +rd (recursive desired) often. Also, if you are looking to invalid DNSSEC records, you might need to use +cd (checking disabled) flag, otherwise the DNS server may not return them.

- see `scripts/validate.py` to see a full validation and run for example `scripts/validate.py metebalci.com A`.

```
./validate.py metebalci.com A /tmp 8.8.8.8
saving _root.DS (trust anchor)
digsec download +save-root-anchors=/tmp/root-anchors.xml +save-ds-anchors=/tmp/_root.IN
digsec v0.8.1
Trust-Anchor contains keytags: 19036-8, 20326-8
validating trust anchor
openssl smime -verify -CAfile /tmp/root-anchors.xml.ca -inform der -in /tmp/root-anchors.xml.p7s -content /tmp/root-anchors.xml
<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="380DC50D-484E-40D0-A3AE-68F2B18F61C7" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
</KeyDigest>
<KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
<KeyTag>20326</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
</KeyDigest>
</TrustAnchor>
Verification successful
--- querying ---
saving _root.DNSKEY
digsec query @8.8.8.8 . DNSKEY +rd +cd +do +udp_payload_size=2048 +save-answer +save-answer-dir=/tmp
digsec v0.8.1
saving com.DS
digsec query @8.8.8.8 com DS +rd +cd +do +udp_payload_size=2048 +save-answer +save-answer-dir=/tmp
digsec v0.8.1
saving com.DNSKEY
digsec query @8.8.8.8 com DNSKEY +rd +cd +do +udp_payload_size=2048 +save-answer +save-answer-dir=/tmp
digsec v0.8.1
saving metebalci.com.DS
digsec query @8.8.8.8 metebalci.com DS +rd +cd +do +udp_payload_size=2048 +save-answer +save-answer-dir=/tmp
digsec v0.8.1
saving metebalci.com.DNSKEY
digsec query @8.8.8.8 metebalci.com DNSKEY +rd +cd +do +udp_payload_size=2048 +save-answer +save-answer-dir=/tmp
digsec v0.8.1
saving metebalci.com.A
digsec query @8.8.8.8 metebalci.com A +rd +cd +do +udp_payload_size=2048 +save-answer +save-answer-dir=/tmp
digsec v0.8.1
--- validating ---
validating _root.DNSKEY with _root.DS (trust anchor)
digsec validate /tmp/_root.IN.DNSKEY /tmp/_root.IN.RRSIG.DNSKEY /tmp/_root.IN.DS
digsec v0.8.1
OK RRSIG (DNSKEY, RSASHA256) with DNSKEY (20326, RSASHA256)
OK DNSKEY (20326, RSASHA256) with DS (SHA-256)
validating com.DS with _root.DNSKEY
digsec validate /tmp/com.IN.DS /tmp/com.IN.RRSIG.DS /tmp/_root.IN.DNSKEY
digsec v0.8.1
OK RRSIG (DS, RSASHA256) with DNSKEY (18733, RSASHA256)
validating com.DNSKEY with com.DS
digsec validate /tmp/com.IN.DNSKEY /tmp/com.IN.RRSIG.DNSKEY /tmp/com.IN.DS
digsec v0.8.1
OK RRSIG (DNSKEY, RSASHA256) with DNSKEY (30909, RSASHA256)
OK DNSKEY (30909, RSASHA256) with DS (SHA-256)
validating metebalci.com.DS with com.DNSKEY
digsec validate /tmp/metebalci.com.IN.DS /tmp/metebalci.com.IN.RRSIG.DS /tmp/com.IN.DNSKEY
digsec v0.8.1
OK RRSIG (DS, RSASHA256) with DNSKEY (53929, RSASHA256)
validating metebalci.com.DNSKEY with metebalci.com.DS
digsec validate /tmp/metebalci.com.IN.DNSKEY /tmp/metebalci.com.IN.RRSIG.DNSKEY /tmp/metebalci.com.IN.DS
digsec v0.8.1
OK RRSIG (DNSKEY, ECDSAP256SHA256) with DNSKEY (2371, ECDSAP256SHA256)
OK DNSKEY (2371, ECDSAP256SHA256) with DS (SHA-256)
validating metebalci.com.A with metebalci.com.DNSKEY
digsec validate /tmp/metebalci.com.IN.A /tmp/metebalci.com.IN.RRSIG.A /tmp/metebalci.com.IN.DNSKEY
digsec v0.8.1
OK RRSIG (A, ECDSAP256SHA256) with DNSKEY (34505, ECDSAP256SHA256)
```

# Known Issues

- `scripts/validate.py` does not work with 2+ level domains e.g. www.metebalci.com

# Release History

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
