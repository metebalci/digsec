# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
handles download command
"""
import os
import urllib.request
import xml.dom.minidom
import binascii
from digsec import DigsecError
from digsec.answer import save_section
from digsec.utils import parse_flags, dprint
from digsec.messages import L2_RR_DS
from digsec.utils import dnssec_algorithm_to_str, dnssec_digest_type_to_str

# using an embedded CA cert eliminates any potential issue with HTTPS
# extracted from root-anchors.p7s file
# exported as base-64 encoded X.509
ICANN_ROOT_CA_CERT = '''
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBdMQ4wDAYDVQQKEwVJQ0FO
TjEmMCQGA1UECxMdSUNBTk4gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNV
BAMTDUlDQU5OIFJvb3QgQ0ExCzAJBgNVBAYTAlVTMB4XDTA5MTIyMzA0MTkxMloX
DTI5MTIxODA0MTkxMlowXTEOMAwGA1UEChMFSUNBTk4xJjAkBgNVBAsTHUlDQU5O
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1JQ0FOTiBSb290IENB
MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKDb
cLhPNNqc1NB+u+oVvOnJESofYS9qub0/PXagmgr37pNublVThIzyLPGCJ8gPms9S
G1TaKNIsMI7d+5IgMy3WyPEOECGIcfqEIktdR1YWfJufXcMReZwU4v/AdKzdOdfg
ONiwc6r70duEr1IiqPbVm5T05l1e6D+HkAvHGnf1LtOPGs4CHQdpIUcy2kauAEy2
paKcOcHASvbTHK7TbbvHGPB+7faAztABLoneErruEcumetcNfPMIjXKdv1V1E3C7
MSJKy+jAqqQJqjZoQGB0necZgUMiUv7JK1IPQRM2CXJllcyJrm9WFxY0c1KjBO29
iIKK69fcglKcBuFShUECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAf4wHQYDVR0OBBYEFLpS6UmDJIZSL8eZzfyNa2kITcBQMA0GCSqGSIb3
DQEBCwUAA4IBAQAP8emCogqHny2UYFqywEuhLys7R9UKmYY4suzGO4nkbgfPFMfH
6M+Zj6owwxlwueZt1j/IaCayoKU3QsrYYoDRolpILh+FPwx7wseUEV8ZKpWsoDoD
2JFbLg2cfB8u/OlE4RYmcxxFSmXBg0yQ8/IoQt/bxOcEEhhiQ168H2yE5rxJMt9h
15nu5JBSewrCkYqYYmaxyOC3WrVGfHZxVI7MpIFcGdvSb2a1uyuua8l0BKgk3ujF
0/wsHNeP22qNyVO+XVBzrM8fk8BSUFuiT/6tZTYXRtEt5aKQZgXbKU5dUF3jT9qg
j/Br5BZw3X/zd325TvnswzMC1+ljLzHnQGGk
-----END CERTIFICATE-----
'''

def __read_text_node(parent, tagname):
    for e in parent.getElementsByTagName(tagname):
        for c in e.childNodes:
            if c.nodeType == xml.dom.Node.TEXT_NODE:
                return c.data
    return None


def __read_trust_anchor(s):
    trust_anchors = []
    dom = xml.dom.minidom.parseString(s)
    for ta in dom.getElementsByTagName("TrustAnchor"):
        for kd in ta.getElementsByTagName("KeyDigest"):
            keytag = int(__read_text_node(kd, 'KeyTag'))
            algorithm = int(__read_text_node(kd, 'Algorithm'))
            digest_type = int(__read_text_node(kd, 'DigestType'))
            digest = binascii.unhexlify(__read_text_node(kd, 'Digest'))
            ds_rr = L2_RR_DS('',
                             'IN',
                             60 * 60,
                             keytag,
                             dnssec_algorithm_to_str(algorithm),
                             dnssec_digest_type_to_str(digest_type),
                             digest).to_rr()
            trust_anchors.append((keytag, algorithm, ds_rr))
    return trust_anchors


def do_download(argv):
    default_flags = {'save-ds-anchors': None,
                     'save-root-anchors': None,
                     'root-anchors-location': 'https://data.iana.org/root-anchors'}
    flags = parse_flags(argv, default_flags)
    dprint(flags)
    ds_anchors_filename = flags['save-ds-anchors']
    root_anchors_filename = flags['save-root-anchors']
    root_anchors_location = flags['root-anchors-location']
    is_remote = root_anchors_location.startswith('http')
    if is_remote:
        try:
            with urllib.request.urlopen(root_anchors_location + '/root-anchors.xml') as r:
                trust_anchors_xml = r.read()
        except:
            # pylint: disable=raise-missing-from
            raise DigsecError('cannot read ' \
                              '%s/root-anchors.xml' % root_anchors_location)
    else:
        with open(root_anchors_location, 'rb') as r:
            trust_anchors_xml = r.read()
    trust_anchors = __read_trust_anchor(trust_anchors_xml.decode('utf-8'))
    if root_anchors_filename is not None:
        if is_remote:
            try:
                with urllib.request.urlopen(root_anchors_location + "/root-anchors.p7s") as r:
                    trust_anchors_xml_signature = r.read()
            except:
                # pylint: disable=raise-missing-from
                raise DigsecError('cannot read ' \
                                  '%s/root-anchors.p7s' % root_anchors_location)
    print('Trust-Anchor contains keytags: %s' %
          ', '.join(map(lambda k: '%s-%s' % (k[0], k[1]),
                        trust_anchors)))
    if ds_anchors_filename is None and root_anchors_filename is None:
        print('Use +save flags to actually save the anchors')
    else:
        if ds_anchors_filename:
            save_section(os.getcwd(),
                         ds_anchors_filename,
                         map(lambda x: x[2], trust_anchors))
        if root_anchors_filename:
            with open(root_anchors_filename, "wb") as f:
                f.write(trust_anchors_xml)
            if is_remote:
                with open(root_anchors_filename + ".p7s", "wb") as f:
                    f.write(trust_anchors_xml_signature)
                with open(root_anchors_filename + ".ca", "wt", encoding='ascii') as f:
                    f.write(ICANN_ROOT_CA_CERT)
