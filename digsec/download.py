import os
from digsec.answer import save_rrset
from digsec.help import display_help_download
from digsec.utils import parse_flags, dprint
from digsec.messages import L2_RR_DS
from digsec.utils import dnssec_algorithm_to_str, dnssec_digest_type_to_str
import urllib.request
import xml.dom.minidom
import binascii


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
    default_flags = {'save-ds-anchors': '',
                     'save-root-anchors': ''}
    flags = parse_flags(argv, default_flags)
    dprint(flags)
    ds_anchors_filename = flags['save-ds-anchors']
    root_anchors_filename = flags['save-root-anchors']
    root_anchors_url = 'https://data.iana.org/root-anchors/root-anchors.xml'
    r = urllib.request.urlopen(root_anchors_url)
    b = r.read()
    trust_anchors = __read_trust_anchor(b.decode('utf-8'))
    print('Trust-Anchor contains keytags: %s' %
          ', '.join(map(lambda k: '%s-%s' % (k[0], k[1]),
                        trust_anchors)))
    if len(ds_anchors_filename) == 0 and len(root_anchors_filename) == 0:
        print('Use +save flags to actually save the anchors')
    else:
        if ds_anchors_filename:
            save_rrset(os.getcwd(),
                       ds_anchors_filename,
                       map(lambda x: x[2], trust_anchors))
        if root_anchors_filename:
            with open(root_anchors_filename, "wb") as f:
                f.write(b)
