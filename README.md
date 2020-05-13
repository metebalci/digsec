# digsec

[![Build Status](https://travis-ci.com/metebalci/digsec.svg?branch=master)](https://travis-ci.com/metebalci/digsec)

dig like command line utility to understand DNSSEC.

# Install

`pip install digsec`

# Usage

Just run digsec to see options and help, or see this blog post https://metebalci.com/blog/a-minimum-complete-tutorial-of-dnssec/ .

# Hints

- digsec do not add DNS flags implicitly. You might need to use +rd (recursive desired) often.

- see scripts/validate_second_level_domain.sh and run it to see a full validation.

# Notes

ECDSAP384SHA384, RSA-512 and SHA-384 support is not tested. If you know a domain using these algorithms, please let me know.

# Release History

0.5:
  - Preliminary support for ECDSAP384SHA384, RSA-512, SHA-384.
  - Server the DNS packet is sent is written under NETWORK COMMUNICATION line.
  - digsec version is written at first line in the output as digsec vX.

0.4: 
  - ECDSAP256SHA256 implemented. 
  - @server option added. 
  - validate_second_level_domain.sh script added.
