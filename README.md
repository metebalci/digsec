# digsec

[![CircleCI](https://circleci.com/gh/metebalci/digsec/tree/master.svg?style=svg)](https://circleci.com/gh/metebalci/digsec/tree/master)

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
