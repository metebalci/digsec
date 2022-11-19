# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
import unittest
import base64
from digsec.messages import DNSRR
from digsec.validate import validate_rrsig, validate_dnskey

# RFC8080 test data is from Errata

class TestAlgorithms(unittest.TestCase):

    def test_ed25519_RFC8080_TestData1(self):

        dnskey = """
        example.com. 3600 IN DNSKEY 257 3 15 (
        l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= )
        """
        dnskey = DNSRR.from_presentation(dnskey)
        ds = """
        example.com. 3600 IN DS 3613 15 2 (
                     3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79
                     a304b )
        """
        ds = DNSRR.from_presentation(ds)
        mx = """
        example.com. 3600 IN MX 10 mail.example.com.
        """
        mx = DNSRR.from_presentation(mx)
        rrsig = """
        example.com. 3600 IN RRSIG MX 15 2 3600 (
                     1440021600 1438207200 3613 example.com. (
                     oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3f
                     x8A4M3e23mRZ9VrbpMngwcrqNAg== )
        """
        rrsig = DNSRR.from_presentation(rrsig)
        validate_rrsig([mx], rrsig, [dnskey])

    def test_ed25519_RFC8080_TestData2(self):

        dnskey = """
        example.com. 3600 IN DNSKEY 257 3 15 (
                     zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs= )
        """
        dnskey = DNSRR.from_presentation(dnskey)
        ds = """
        example.com. 3600 IN DS 35217 15 2 (
                     401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c
                     6614c )
        """
        ds = DNSRR.from_presentation(ds)
        mx = """
        example.com. 3600 IN MX 10 mail.example.com.
        """
        mx = DNSRR.from_presentation(mx)
        rrsig = """
        example.com. 3600 IN RRSIG MX 15 2 3600 (
                     1440021600 1438207200 35217 example.com. (
                     zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQ
                     oSm5poJ7gD7AQR0O7KuI5k2pcBg== )
        """
        rrsig = DNSRR.from_presentation(rrsig)
        validate_rrsig([mx], rrsig, [dnskey])

    def test_ed448_RFC8080_TestData1(self):

        dnskey = """
        example.com. 3600 IN DNSKEY 257 3 16 (
             3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx
             1FYYUcJKm1MDpJtIA )
        """
        dnskey = DNSRR.from_presentation(dnskey)
        ds = """
        example.com. 3600 IN DS 9713 16 2 (
             6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2
             b19c7 )
        """
        ds = DNSRR.from_presentation(ds)
        mx = """
        example.com. 3600 IN MX 10 mail.example.com.
        """
        mx = DNSRR.from_presentation(mx)
        rrsig = """
        example.com. 3600 IN RRSIG MX 16 2 3600 (
             1440021600 1438207200 9713 example.com. (
             3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0am
             xWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/
             JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA )
        """
        rrsig = DNSRR.from_presentation(rrsig)
        validate_rrsig([mx], rrsig, [dnskey])

    def test_ed448_RFC8080_TestData2(self):

        dnskey = """
        example.com. 3600 IN DNSKEY 257 3 16 (
             kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcN
             Lp5HlHAMy12VoISsA )
        """
        dnskey = DNSRR.from_presentation(dnskey)
        ds = """
        example.com. 3600 IN DS 38353 16 2 (
             645ff078b3568f5852b70cb60e8e696cc77b75bfaaffc118cf79cbda1ba
             28af4 )
        """
        ds = DNSRR.from_presentation(ds)
        mx = """
        example.com. 3600 IN MX 10 mail.example.com.
        """
        mx = DNSRR.from_presentation(mx)
        rrsig = """
        example.com. 3600 IN RRSIG MX 16 2 3600 (
             1440021600 1438207200 38353 example.com. (
             E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4Sp8Syg1eI+lJ57C
             SnZqjJP41O/9l4m0AsQ4f7qI1gVnML8vWWiyW2KXhT9kuAICUSxv5OWbf81
             Rq7Yu60npabODB0QFPb/rkW3kUZmQ0YQUA )
        """
        rrsig = DNSRR.from_presentation(rrsig)
        validate_rrsig([mx], rrsig, [dnskey])
