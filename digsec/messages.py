# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
# pylint: disable=missing-class-docstring
# pylint: disable=too-many-lines
"""
handles DNS messages
"""
import base64
import binascii
from collections import namedtuple
from datetime import datetime
from struct import pack, unpack
from digsec import dprint, DigsecError
from digsec.utils import format_ipv6_addr
from digsec.utils import l2s, dns_class_to_int, dns_type_to_int
from digsec.utils import dns_opcode_to_str, dns_rcode_to_str
from digsec.utils import dns_class_to_str, dns_type_to_str
from digsec.utils import dnssec_algorithm_to_int, dnssec_algorithm_to_str
from digsec.utils import dnssec_digest_type_to_int, dnssec_digest_type_to_str
from digsec.utils import decode_name, encode_name, calculate_keytag
from digsec.utils import dnssec_nsec3_algorithm_to_str
from digsec.constants import EDNS0_OPT_CODES_TO_STR, EDNS_ERR_CODES_TO_STR

# Some explanation on how this module works
#
# DNS... classes are basic, works on raw packets
# L2 classes are abstract, with type specific functionality

# There are a few ways to serialize/deserialize
#
# - to_packet->bytes, from_packet(bytes)
# - from_rr(DNSRR)
# - from_presentation(text)
#
# DNSRR is converted L2 by DNSRR.l2() which calls L2.from_rr() to parse rdata
# L2 is converted to DNSRR by L2.canonical_l1()
#
# it is better to use from_presentation to directly instantiating L2 class
# internally from_presentation creates a low level DNSRR with raw rdata and
# then uses from_rr

# For query, from_packet is used with data fetched from network
#            to_packet is used to save answer file
# For validate and view, from_packet is used when reading from answer file
# For test, from_presentation is used

class DNSMessage(namedtuple('DNSMessage', ['header',
                                           'question',
                                           'answer',
                                           'authority',
                                           'additional'])):
    __slots__ = ()

    def to_packet(self):
        b = bytearray()
        b.extend(self.header.to_packet())
        for section in [self.question,
                        self.answer,
                        self.authority,
                        self.additional]:
            for rr in section:
                b.extend(rr.to_packet())
        return b

    @staticmethod
    def from_packet(packet):
        header = DNSHeader.from_packet(packet)
        # 12 is fixed because header is always 12 octets
        offset = 12
        question = []
        answer = []
        authority = []
        additional = []
        for count, section, rrclass in zip([header.qdcount,
                                            header.ancount,
                                            header.nscount,
                                            header.arcount],
                                           [question,
                                            answer,
                                            authority,
                                            additional],
                                           [DNSQuestionRR,
                                            DNSRR,
                                            DNSRR,
                                            DNSRR]):
            for _i in range(0, count):
                rr, newoffset = rrclass.from_packet(packet, offset)
                if isinstance(rr, DNSRR) and rr.typ == dns_type_to_int('OPT'):
                    rr, newoffset = DNSOptRR.from_packet(packet, offset)
                offset = newoffset
                section.append(rr)
        return DNSMessage(header,
                          question,
                          answer,
                          authority,
                          additional)

    def __str__(self):
        return ('--- Header ---\n%s\n' +
                '--- Question ---\n%s\n' +
                '--- Answer ---\n%s\n' +
                '--- Authority ---\n%s\n' +
                '--- Additional ---\n%s') % (self.header,
                                             l2s(self.question),
                                             l2s(self.answer),
                                             l2s(self.authority),
                                             l2s(self.additional))

    def __repr__(self):
        return self.__str__()

    def l2(self):
        return L2_Message.from_L1(self)


class DNSHeader(namedtuple('DNSHeader', ['id',
                                         'flags',
                                         'qdcount',
                                         'ancount',
                                         'nscount',
                                         'arcount'])):
    __slots__ = ()

    def to_packet(self):
        return pack('! H 2s H H H H',
                    self.id,
                    self.flags.to_packet(),
                    self.qdcount,
                    self.ancount,
                    self.nscount,
                    self.arcount)

    @staticmethod
    def from_packet(packet):
        (msgid,
         flags,
         qdcount,
         ancount,
         nscount,
         arcount) = unpack('! H H H H H H', packet[0:12])
        return DNSHeader(msgid,
                         DNSFlags((flags >> 15) & 0b1 != 0,
                                  (flags >> 11) & 0b1111,
                                  (flags >> 10) & 0b1 != 0,
                                  (flags >> 9) & 0b1 != 0,
                                  (flags >> 8) & 0b1 != 0,
                                  (flags >> 7) & 0b1 != 0,
                                  # omit z
                                  (flags >> 5) & 0b1 != 0,
                                  (flags >> 4) & 0b1 != 0,
                                  flags & 0b1111),
                         qdcount,
                         ancount,
                         nscount,
                         arcount)

    def __str__(self):
        return ('ID: %d\n' +
                'FLAGS: %s\n' +
                'QDCOUNT: %d\n' +
                'ANCOUNT: %d\n' +
                'NSCOUNT: %d\n' +
                'ARCOUNT: %d') % (self.id,
                                  self.flags,
                                  self.qdcount,
                                  self.ancount,
                                  self.nscount,
                                  self.arcount)

    def __repr__(self):
        return self.__str__()


class DNSFlags(namedtuple('DNSFlags', ['qr',
                                       'opcode',
                                       'aa',
                                       'tc',
                                       'rd',
                                       'ra',
                                       'ad',
                                       'cd',
                                       'rcode'])):
    __slots__ = ()

    @property
    def opcode_str(self):
        return dns_opcode_to_str(self.opcode)

    @property
    def rcode_str(self):
        return dns_rcode_to_str(self.rcode)

    def to_packet(self):
        x = 0
        x = x << 1
        if self.qr:
            x = x | 0b1
        x = x << 4
        x = x | self.opcode
        for f in [self.aa,
                  self.tc,
                  self.rd,
                  self.ra,
                  0,  # z
                  self.ad,
                  self.cd]:
            x = x << 1
            if f:
                x = x | 0b1
        x = x << 4
        x = x | self.rcode
        return pack('! H', x)

    def __str__(self):
        fs = []
        fs.append('QR' if self.qr else '__')
        fs.append('%04X' % self.opcode)
        fs.append('AA' if self.aa else '__')
        fs.append('TC' if self.tc else '__')
        fs.append('RD' if self.rd else '__')
        fs.append('RA' if self.ra else '__')
        fs.append('AD' if self.ad else '__')
        fs.append('CD' if self.cd else '__')
        fs.append('%04X' % self.rcode)
        return '%s' % (' '.join(fs))

    def __repr__(self):
        return self.__str__()


# q means query
# qname is name + any/* and a few others
# qclass is class + any/*
class DNSQuestionRR(namedtuple('DNSQuestionRR', ['qname',
                                                 'qtype',
                                                 'qclass'])):
    __slots__ = ()

    @property
    def qtype_str(self):
        return dns_type_to_str(self.qtype)

    @property
    def qclass_str(self):
        return dns_class_to_str(self.qclass)

    def to_packet(self):
        b = bytearray()
        if self.qname == '':
            b.append(0)
        else:
            # standard dns name notation, len label len label null
            for qnamepart in self.qname.split('.'):
                b.append(len(qnamepart))
                b.extend(qnamepart.encode('ascii'))
            b.append(0)
        b.extend(pack('! H H', self.qtype, self.qclass))
        return b

    @staticmethod
    def from_packet(packet, offset):
        (qname, offset) = decode_name(packet, offset)
        (qtype, qclass) = unpack('! H H', packet[offset:offset + 4])
        return DNSQuestionRR(qname,
                             qtype,
                             qclass), offset + 4

    def __str__(self):
        return '%s %d(%s) %d(%s)' % (self.qname,
                                     self.qtype,
                                     self.qtype_str,
                                     self.qclass,
                                     self.qclass_str)

    def __repr__(self):
        return self.__str__()

    def l2(self):
        return L2_QRR.from_L1(self)


class DNSRR(namedtuple('DNSRR', ['name',
                                 'typ',  # type
                                 'clas',  # class
                                 'ttl',
                                 'rdlength',
                                 'rdata',
                                 'orig_packet',
                                 'orig_rdataoffset'])):
    __slots__ = ()

    @property
    def type_str(self):
        return dns_type_to_str(self.typ)

    @property
    def class_str(self):
        return dns_class_to_str(self.clas)

    def to_packet(self):
        b = bytearray()
        b.extend(encode_name(self.name))
        b.extend(pack('! H H i H',
                      self.typ,
                      self.clas,
                      self.ttl,
                      self.rdlength))
        if self.rdlength > 0:
            b.extend(self.rdata)
        return b

    @staticmethod
    def from_packet(packet, offset):
        (name, offset) = decode_name(packet, offset)
        dprint('name: "%s", offset: %d' % (name, offset))
        (typ,
         clas,
         ttl,
         rdlength) = unpack('! H H i H',
                            packet[offset:offset + 10])
        dprint('type: %d, clas: %d, ttl: %d' % (typ, clas, ttl))
        rdata = packet[offset + 10:offset + 10 + rdlength]
        dprint('rdata (%d): 0x%s' % (len(rdata), binascii.hexlify(rdata).decode('ascii')))
        return (DNSRR(name,
                      typ,
                      clas,
                      ttl,
                      rdlength,
                      rdata,
                      packet,
                      offset + 10),
                offset + 10 + rdlength)

    @staticmethod
    def from_presentation(p):
        pa = []
        # in case presentation contains \n or \r remote them first
        # remove empty parts/spaces
        # also remove paranthesis, not needed for reading
        for part in (p
                     .replace('\n', '')
                     .replace('\r', '')
                     .replace('(', '')
                     .replace(')', '')
                     .split(' ')
                     ):
            if part == '':
                pass
            elif part == ' ':
                pass
            else:
                pa.append(part)
        name = pa[0]
        ttl = int(pa[1])
        clas = pa[2]
        typ = pa[3]
        if typ == 'DNSKEY':
            return L2_RR_DNSKEY.from_presentation(name, ttl, clas, pa[4:])
        elif typ == 'DS':
            return L2_RR_DS.from_presentation(name, ttl, clas, pa[4:])
        elif typ == 'RRSIG':
            return L2_RR_RRSIG.from_presentation(name, ttl, clas, pa[4:])
        elif typ == 'MX':
            return L2_RR_MX.from_presentation(name, ttl, clas, pa[4:])
        else:
            return DigsecError('RR type: %s not supported to read from presentation' % typ)

    def __str__(self):
        return '%s %d(%s) %d(%s) %d %d 0x%s' % (self.name,
                                                self.typ,
                                                self.type_str,
                                                self.clas,
                                                self.class_str,
                                                self.ttl,
                                                self.rdlength,
                                                binascii.hexlify(self.rdata)
                                                .decode('ascii'))

    def __repr__(self):
        return self.__str__()

    def l2(self):
        m = {}
        m['A'] = L2_RR_A
        m['AAAA'] = L2_RR_AAAA
        m['MX'] = L2_RR_MX
        m['TXT'] = L2_RR_TXT
        m['NS'] = L2_RR_NS
        m['SOA'] = L2_RR_SOA
        m['DNSKEY'] = L2_RR_DNSKEY
        m['NSEC'] = L2_RR_NSEC
        m['RRSIG'] = L2_RR_RRSIG
        m['NSEC3'] = L2_RR_NSEC3
        m['DS'] = L2_RR_DS
        t = dns_type_to_str(self.typ)
        for k, v in m.items():
            if k == t:
                return v.from_rr(self)
        return None


# OPT pseudo-RR, RFC 2671
# Although it is a normal RR, I created a special class for this
# because it changes the meanings of class and ttl fields
class DNSOptRR(namedtuple('DNSOptRR', ['udp_payload_size',
                                       'extended_rcode',
                                       'version',
                                       'DO',
                                       'options'])):
    __slots__ = ()

    @property
    def name(self):
        return ''

    @property
    def typ(self):
        return 41

    @property
    def type_str(self):
        return 'OPT'

    def to_packet(self):
        b = bytearray()
        # no name in OPT record
        b.append(0)
        # class is replaced by udp_payload_size
        # ttl is replaced by extended_rcode, version, DO bit and Zeroes
        b.extend(pack('! H H B B B B',
                      self.typ,
                      self.udp_payload_size,
                      self.extended_rcode,
                      self.version,
                      0b10000000 if self.DO else 0,
                      0))
        # write options to rdata first
        rdata = bytearray()
        for (option_code, option_data) in self.options:
            rdata.extend(pack('! H H', option_code, len(option_data)))
            rdata.extend(option_data)
        b.extend(pack('! H', len(rdata)))
        b.extend(rdata)
        return b

    # pylint: disable=too-many-locals
    @staticmethod
    def from_packet(packet, offset):
        (_name,
         _typ,
         udp_payload_size,
         extended_rcode,
         version,
         DO,
         _Z,
         rdlength) = unpack('! B H H B B B B H',
                            packet[offset:offset + 11])
        DO = ((DO & 0b10000000) != 0)
        rdata = packet[offset + 11:offset + 11 + rdlength]
        rdataoffset = 0
        options = []
        while rdataoffset < rdlength:
            (option_code, option_length) = unpack('! H H',
                                                  rdata[rdataoffset:
                                                        rdataoffset+4])
            option_data = rdata[rdataoffset + 4:
                                rdataoffset + 4 + option_length]
            options.append((option_code, option_data))
            rdataoffset = rdataoffset + 4 + option_length
        return DNSOptRR(udp_payload_size,
                        extended_rcode,
                        version,
                        DO,
                        options), offset + 11 + rdlength

    def __str__(self):
        opts = []
        for (option_code, option_data) in self.options:
            opts.append('%s:0x%s' % (option_code,
                                     binascii.hexlify(option_data)
                                     .decode('ascii')))
        return '%s %d(%s) %d (%d %d %d) [%s]' % (self.name,
                                                 self.typ,
                                                 self.type_str,
                                                 self.udp_payload_size,
                                                 self.extended_rcode,
                                                 self.version,
                                                 self.DO,
                                                 ', '.join(opts))

    def __repr__(self):
        return self.__str__()

    # pylint: disable=no-self-use
    def l2(self):
        return None


class L2_Message(namedtuple('L2_Message', ['id',
                                           'qr',
                                           'opcode',
                                           'aa',
                                           'tc',
                                           'rd',
                                           'ra',
                                           'ad',
                                           'cd',
                                           'rcode',
                                           'extended_rcode',
                                           'edns',
                                           'question',
                                           'answer',
                                           'authority',
                                           'additional'])):

    __slots__ = ()

    @staticmethod
    def from_L1(l1):
        edns = None
        if len(l1.additional) > 0:
            for rr in l1.additional:
                if rr.type_str == 'OPT':
                    edns = L2_EDNS(rr.udp_payload_size,
                                   rr.extended_rcode,
                                   rr.version,
                                   rr.DO,
                                   rr.options)
                    break
        if edns is not None:
            extended_rcode = (edns.extended_rcode << 4) | l1.header.flags.rcode
        else:
            extended_rcode = l1.header.flags.rcode

        def list_to_l2(l):
            return list(filter(lambda x: x is not None,
                               map(lambda rr: rr.l2(),
                                   l)))

        return L2_Message(l1.header.id,
                          l1.header.flags.qr,
                          dns_opcode_to_str(l1.header.flags.opcode),
                          l1.header.flags.aa,
                          l1.header.flags.tc,
                          l1.header.flags.rd,
                          l1.header.flags.ra,
                          l1.header.flags.ad,
                          l1.header.flags.cd,
                          dns_rcode_to_str(l1.header.flags.rcode),
                          dns_rcode_to_str(extended_rcode),
                          edns,
                          list_to_l2(l1.question),
                          list_to_l2(l1.answer),
                          list_to_l2(l1.authority),
                          list_to_l2(l1.additional))

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        flags = []
        flags.append('Flags:')
        if self.qr:
            flags.append('\tThis is a Reply, QR=1')
        else:
            flags.append('\tThis is a Question, QR=0')
        flags.append('\tOpcode: %s' % self.opcode)
        if self.aa:
            flags.append('\tThis is an Authoritative Answer, AA=1')
        if self.tc:
            flags.append('\tThis answer is TrunCated, TC=1')
        if self.rd:
            flags.append('\tRecursive Desired for the answer, RD=1')
        if self.rd:
            flags.append('\tRecursive Available, RA=1')
        if self.ad:
            flags.append('\tDNSSEC Authenticated Data, AD=1')
        if self.cd:
            flags.append('\tDNSSEC Checking Disabled, CD=1')
        flags.append('\tRCODE: %s' % self.rcode)
        flags = '\n'.join(flags)

        return ('ID: %s\n' +
                '%s\n' +
                '%s\n' +
                '--- Question ---\n%s\n' +
                '--- Answer ---\n%s\n' +
                '--- Authority ---\n%s\n' +
                '--- Additional (not showing OPT here, ' +
                'see EDNS above) ---\n%s') % (self.id,
                                              flags,
                                              self.edns if self.edns is not None
                                              else 'No Extension (EDNS)',
                                              l2s(self.question),
                                              l2s(self.answer),
                                              l2s(self.authority),
                                              l2s(self.additional))


class L2_EDNS(namedtuple('L2_EDNS', ['udp_payload_size',
                                     'extended_rcode',
                                     'version',
                                     'dnssec_ok',
                                     'options'])):

    __slots__ = ()

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        opts = []
        opts.append('Extension (EDNS):')
        opts.append('\tUDP payload size: %d' % self.udp_payload_size)
        opts.append('\tEXTENDED-RCODE: %s' % self.extended_rcode)
        opts.append('\tVERSION: %d' % self.version)
        opts.append('\tDNSSEC OK (DO): %s' % self.dnssec_ok)
        opts.append('\tOptions: ')
        for opt in self.options:
            option_code = opt[0]
            option_code_str = EDNS0_OPT_CODES_TO_STR.get(option_code,
                                                         None)
            option_data = opt[1]
            opts.append('\t\t%d (%s)' % (option_code,
                                         option_code_str))
            # option_code=15
            # Extended DNS Errors (RFC 8914)
            if option_code == 15:
                info_code, = unpack('! H', option_data[0:2])
                extra_text = option_data[2:].decode('ascii')
                opts[-1] = ('%s: %d (%s) "%s"' % (opts[-1],
                                               info_code,
                                               EDNS_ERR_CODES_TO_STR.get(info_code, ''),
                                               extra_text))
        return '\n'.join(opts)


class L2_QRR(namedtuple('L2_QRR', ['qname',
                                   'qtype',
                                   'qclass'])):

    __slots__ = ()

    @staticmethod
    def from_L1(qrr):
        return L2_QRR(qrr.qname,
                      dns_type_to_str(qrr.qtype),
                      dns_class_to_str(qrr.qclass))

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %s %s' % (self.qname,
                             self.qtype,
                             self.qclass)


class L2_RR_A(namedtuple('L2_RR_A', ['name',
                                     'clas',
                                     'ttl',
                                     'address'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'A'

    # RFC 4034 Section 6.2
    def canonical_l1(self, ttl):
        rdata = bytearray()
        for part in self.address.split('.'):
            rdata.append(int(part))
        return DNSRR(self.name.lower(),
                     dns_type_to_int(self.typ),
                     dns_class_to_int('IN'),
                     ttl,
                     4,
                     rdata,
                     None,
                     None)

    @staticmethod
    def from_rr(rr):
        address = '%d.%d.%d.%d' % (rr.rdata[0],
                                   rr.rdata[1],
                                   rr.rdata[2],
                                   rr.rdata[3])
        return L2_RR_A(rr.name,
                       dns_class_to_str(rr.clas),
                       rr.ttl,
                       address)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d %s %s %s' % (self.name,
                                   self.ttl,
                                   self.clas,
                                   self.typ,
                                   self.address)


class L2_RR_AAAA(namedtuple('L2_RR_AAAA', ['name',
                                           'clas',
                                           'ttl',
                                           'address'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'AAAA'

    # RFC 4034 Section 6.2
    def canonical_l1(self, ttl):
        rdata = bytearray()
        for part in self.address.split(':'):
            first = part[0:2]
            second = part[2:4]
            rdata.append(int(first, 16))
            rdata.append(int(second, 16))
        return DNSRR(self.name.lower(),
                     dns_type_to_int(self.typ),
                     dns_class_to_int('IN'),
                     ttl,
                     4,
                     rdata,
                     None,
                     None)

    @staticmethod
    def from_rr(rr):
        address = '%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x' \
            ':%02x%02x:%02x%02x:%02x%02x' % (
            rr.rdata[0],
            rr.rdata[1],
            rr.rdata[2],
            rr.rdata[3],
            rr.rdata[4],
            rr.rdata[5],
            rr.rdata[6],
            rr.rdata[7],
            rr.rdata[8],
            rr.rdata[9],
            rr.rdata[10],
            rr.rdata[11],
            rr.rdata[12],
            rr.rdata[13],
            rr.rdata[14],
            rr.rdata[15])
        return L2_RR_AAAA(rr.name,
                          dns_class_to_str(rr.clas),
                          rr.ttl,
                          address)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d %s %s %s' % (self.name,
                                   self.ttl,
                                   self.clas,
                                   self.typ,
                                   format_ipv6_addr(self.address))


class L2_RR_TXT(namedtuple('L2_RR_TXT', ['name',
                                         'clas',
                                         'ttl',
                                         'txtdatas'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'TXT'

    # RFC 4034 Section 6.2
    def canonical_l1(self, ttl):
        rdata = bytearray()
        for txtdata in self.txtdatas:
            asbytes = txtdata.encode('ascii')
            rdata.append(len(asbytes))
            rdata.extend(asbytes)
        return DNSRR(self.name.lower(),
                     dns_type_to_int(self.typ),
                     dns_class_to_int('IN'),
                     ttl,
                     len(rdata),
                     rdata,
                     None,
                     None)

    @staticmethod
    def from_rr(rr):
        roffset = 0
        txtdatas = []
        while roffset < len(rr.rdata):
            txtdatalen = rr.rdata[roffset]
            txtdata = rr.rdata[roffset+1:roffset+1+txtdatalen]
            dprint('txtdata: 0x%s' %
                   (binascii.hexlify(txtdata).decode('ascii'),))
            txtdata = bytes(txtdata).decode('ascii')
            dprint('txtdata: %s' % (txtdata,))
            txtdatas.append(txtdata)
            # +1 is txtdatalen itself
            roffset = roffset + txtdatalen + 1
        return L2_RR_TXT(rr.name,
                         dns_class_to_str(rr.clas),
                         rr.ttl,
                         txtdatas)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d %s %s %s' % (self.name,
                                   self.ttl,
                                   self.clas,
                                   self.typ,
                                   '|'.join(self.txtdatas))


class L2_RR_SOA(namedtuple('L2_RR_SOA', ['name',
                                         'clas',
                                         'ttl',
                                         'mname',
                                         'rname',
                                         'serial',
                                         'refresh',
                                         'retry',
                                         'expire',
                                         'minimum'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'SOA'

    # RFC 4034 Section 6.2
    def canonical_l1(self, ttl):
        rdata = bytearray()
        rdata.extend(encode_name(self.mname))
        rdata.extend(encode_name(self.rname))
        rdata.extend(pack('! I I I I I',
                          self.serial,
                          self.refresh,
                          self.retry,
                          self.expire,
                          self.minimum))
        return DNSRR(self.name.lower(),
                     dns_type_to_int(self.typ),
                     dns_class_to_int('IN'),
                     ttl,
                     len(rdata),
                     rdata,
                     None,
                     None)

    @staticmethod
    def from_rr(rr):
        (mname, nextoffset) = decode_name(rr.orig_packet, rr.orig_rdataoffset)
        (rname, nextoffset) = decode_name(rr.orig_packet, nextoffset)
        (serial,
         refresh,
         retry,
         expire,
         minimum) = unpack("! I I I I I",
                           rr.orig_packet[nextoffset:nextoffset+20])
        return L2_RR_SOA(rr.name,
                         dns_class_to_str(rr.clas),
                         rr.ttl,
                         mname,
                         rname,
                         serial,
                         refresh,
                         retry,
                         expire,
                         minimum)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d %s %s %s %s %d %d %d %d %d' % (self.name,
                                                     self.ttl,
                                                     self.clas,
                                                     self.typ,
                                                     self.mname,
                                                     self.rname,
                                                     self.serial,
                                                     self.refresh,
                                                     self.retry,
                                                     self.expire,
                                                     self.minimum)


class L2_RR_NS(namedtuple('L2_RR_NS', ['name',
                                       'clas',
                                       'ttl',
                                       'nsdname'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'NS'

    @staticmethod
    def from_rr(rr):
        nsdname = decode_name(rr.orig_packet, rr.orig_rdataoffset)
        return L2_RR_A(rr.name,
                       dns_class_to_str(rr.clas),
                       rr.ttl,
                       nsdname)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d %s %s %s' % (self.name,
                                   self.ttl,
                                   self.clas,
                                   self.typ,
                                   self.nsdname)


class L2_RR_DNSKEY(namedtuple('L2_RR_DNSKEY', ['name',
                                               'clas',
                                               'ttl',
                                               'keytag',
                                               'flags',
                                               'zone_key',
                                               'sep',
                                               'algorithm',
                                               'public_key',
                                               'digest_data'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'DNSKEY'

    # RFC 4034 Section 6.2
    def canonical_l1(self, ttl):
        rdata = bytearray()
        rdata.extend(pack('! H B B',
                          self.flags,
                          3,
                          dnssec_algorithm_to_int(self.algorithm)))
        rdata.extend(self.public_key)
        return DNSRR(self.name.lower(),
                     dns_type_to_int(self.typ),
                     dns_class_to_int('IN'),
                     ttl,
                     len(rdata),
                     rdata,
                     None,
                     None)

    # RFC 4034 Section 2.2
    @staticmethod
    def from_presentation(name, ttl, clas, pa):
        flags = int(pa[0])
        protocol = int(pa[1])
        algorithm = int(pa[2])
        public_key = ''.join(pa[3:])
        public_key = base64.b64decode(public_key)
        rdata = bytearray()
        rdata.extend(pack('! H B B',
                          flags,
                          protocol,
                          algorithm))
        rdata.extend(public_key)
        rr = DNSRR(name,
                   dns_type_to_int('DNSKEY'),
                   dns_class_to_int(clas),
                   ttl,
                   len(rdata),
                   rdata, 0, 0)
        return L2_RR_DNSKEY.from_rr(rr)

    @staticmethod
    def from_rr(rr):
        digest_data = bytearray()
        # this must be canonical form, so encoding here again
        digest_data.extend(encode_name(rr.name.lower()))
        digest_data.extend(rr.rdata)

        flags, protocol, algorithm = unpack("! H B B",
                                            rr.rdata[0:4])
        # these bits are reserved, MUST be 0
        assert (flags & 0b1111111001111110) == 0
        # protocol has to be 3
        assert protocol == 3
        # bit 7
        # only zone key can be used for RRSIGs
        zone_key = ((flags & 0b0000000100000000) != 0)
        # bit 15
        # secure entry point flag, RFC 3757
        sep = ((flags & 0b0000000000000001) != 0)
        public_key = rr.rdata[4:]
        keytag = calculate_keytag(rr.rdata)
        return L2_RR_DNSKEY(rr.name,
                            dns_class_to_str(rr.clas),
                            rr.ttl,
                            keytag,
                            flags,
                            zone_key,
                            sep,
                            dnssec_algorithm_to_str(algorithm),
                            public_key,
                            digest_data)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d %s %s(%d) %d 3 %s %s' % (self.name,
                                               self.ttl,
                                               self.clas,
                                               self.typ,
                                               self.keytag,
                                               self.flags,
                                               self.algorithm,
                                               base64.b64encode(self.public_key)
                                               .decode('ascii'))

    # RFC 3110
    def rsasha1_public_key(self):
        exponent_length = self.public_key[0]
        off = 1
        if exponent_length == 0:
            exponent_length = unpack('H', self.public_key[1:2])
            off = 3
        exponent = int.from_bytes(self.public_key[off:off+exponent_length],
                                  byteorder='big')
        modulus = int.from_bytes(self.public_key[off+exponent_length:],
                                 byteorder='big')
        return exponent, modulus

    # RFC 5702
    def rsasha256_public_key(self):
        # same format
        return self.rsasha1_public_key()

    # RFC 5702
    def rsasha512_public_key(self):
        # same format
        return self.rsasha1_public_key()

    # RFC 6605
    def ecdsap256sha256_curve_point(self):
        # q is in uncompressed form curve point x | y
        # in uncompressed form, public key len is 2*field_length+1
        # field_length for p256 is 256 bits, thus 32 bytes
        # so uncompressed form public key len is 65 bytes
        q_uncompressed_bytes = self.public_key
        return q_uncompressed_bytes

    # RFC 6605
    def ecdsap384sha384_curve_point(self):
        # same format
        q_uncompressed_bytes = self.public_key
        return q_uncompressed_bytes

    # RFC 8080, 8032
    # 32-octet public key
    def ed25519_curve_point(self):
        y = self.public_key
        sign_of_x = 0 if ((y[31] & 0x80) == 0) else 1
        y[31] = y[31] & 0x7F
        y = int.from_bytes(y, byteorder='little')
        return (sign_of_x, y)

    # RFC 8080
    # 57-octet public key
    def ed448_curve_point(self):
        y = self.public_key
        sign_of_x = 0 if ((y[56] & 0x80) == 0) else 1
        y[56] = y[56] & 0x7F
        y = int.from_bytes(y, byteorder='little')
        return (sign_of_x, y)


class L2_RR_RRSIG(namedtuple('L2_RR_RRSIG', ['name',
                                             'clas',
                                             'ttl',
                                             'type_covered',
                                             'algorithm',
                                             'labels',
                                             'original_ttl',
                                             'signature_expiration',
                                             'signature_inception',
                                             'keytag',
                                             'signers_name',
                                             'signature',
                                             'rrsig_rdata'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'RRSIG'

    # RFC 4034 Section 3.2
    @staticmethod
    def from_presentation(name, ttl, clas, pa):
        type_covered = pa[0]
        algorithm = int(pa[1])
        labels = int(pa[2])
        original_ttl = int(pa[3])
        signature_expiration = pa[4]
        if len(signature_expiration) == 14:
            signature_expiration = int(datetime
                                       .strptime(signature_expiration,
                                                 '%Y%m%d%H%M%S')
                                       .timestamp())
        elif len(signature_expiration) <= 10:
            signature_expiration = int(signature_expiration)
        else:
            raise DigsecError('ERROR: cannot decode signature expiration in ' \
                              'presentation: %s' % pa[4])
        signature_inception = pa[5]
        if len(signature_inception) == 14:
            signature_inception = int(datetime
                                      .strptime(signature_inception,
                                                '%Y%m%d%H%M%S')
                                      .timestamp())
        elif len(signature_inception) <= 10:
            signature_inception = int(signature_inception)
        else:
            raise DigsecError('ERROR: cannot decode signature inception in ' \
                              'presentation: %s' % pa[5])
        keytag = int(pa[6])
        signers_name = pa[7]
        signature = ''.join(pa[8:])
        signature = base64.b64decode(signature)
        rdata = bytearray()
        rdata.extend(pack('! H B B I I I H',
                          dns_type_to_int(type_covered),
                          algorithm,
                          labels,
                          original_ttl,
                          signature_expiration,
                          signature_inception,
                          keytag))
        rdata.extend(encode_name(signers_name))
        rdata.extend(signature)
        rr = DNSRR(name,
                   dns_type_to_int('DS'),
                   dns_class_to_int(clas),
                   ttl,
                   len(rdata),
                   rdata, 0, 0)
        return L2_RR_RRSIG.from_rr(rr)

    @staticmethod
    def from_rr(rr):
        (type_covered,
         algorithm,
         labels,
         original_ttl,
         signature_expiration,
         signature_inception,
         keytag) = unpack("! H B B I I I H", rr.rdata[0:18])
        # no dns name compression allowed for signers_name
        signers_name, offset = decode_name(rr.rdata, 18)
        signature = rr.rdata[offset:]
        return L2_RR_RRSIG(rr.name,
                           dns_class_to_str(rr.clas),
                           rr.ttl,
                           dns_type_to_str(type_covered),
                           dnssec_algorithm_to_str(algorithm),
                           labels,
                           original_ttl,
                           datetime.utcfromtimestamp(signature_expiration),
                           datetime.utcfromtimestamp(signature_inception),
                           keytag,
                           signers_name,
                           signature,
                           rr.rdata[0:offset])

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def ft(tsmp):
        return tsmp.strftime('%Y%m%d%H%M%S')

    @property
    def signature_expiration_str(self):
        return L2_RR_RRSIG.ft(self.signature_expiration)

    @property
    def signature_inception_str(self):
        return L2_RR_RRSIG.ft(self.signature_inception)

    def __str__(self):
        return ('%s %d %s %s %s %s %d %d ' +
                '%s %s %d %s %s') % (self.name,
                                     self.ttl,
                                     self.clas,
                                     self.typ,
                                     self.type_covered,
                                     self.algorithm,
                                     self.labels,
                                     self.original_ttl,
                                     self.signature_expiration_str,
                                     self.signature_inception_str,
                                     self.keytag,
                                     self.signers_name,
                                     base64.b64encode(self.signature)
                                     .decode('ascii'))

# no public_key of L2_RR_RRSIG, is this code used ???
    # RFC 3110
#    def rsasha1_public_key(self):
#        exponent_length = self.public_key[0]
#        off = 1
#        if exponent_length == 0:
#            exponent_length = unpack('H', self.public_key[1:2])
#            off = 3
#        exponent = int.from_bytes(self.public_key[off:off+exponent_length],
#                                  byteorder='big')
#        modulus = int.from_bytes(self.public_key[off+exponent_length:],
#                                 byteorder='big')
#        return exponent, modulus

    # RFC 5702
#    def rsasha256_public_key(self):
        # same format
#       return self.rsasha1_public_key()

    # RFC 5702
#    def rsasha512_public_key(self):
        # same format
#        return self.rsasha1_public_key()


class L2_RR_DS(namedtuple('L2_RR_DS', ['name',
                                       'clas',
                                       'ttl',
                                       'keytag',
                                       'algorithm',
                                       'digest_type',
                                       'digest'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'DS'

    # RFC 4034 Section 5.3
    @staticmethod
    def from_presentation(name, ttl, clas, pa):
        keytag = int(pa[0])
        algorithm = int(pa[1])
        digest_type = int(pa[2])
        digest = ''.join(pa[3:])
        digest = base64.b64decode(digest)
        rdata = bytearray()
        rdata.extend(pack('! H B B',
                          keytag,
                          algorithm,
                          digest_type))
        rdata.extend(digest)
        rr = DNSRR(name,
                   dns_type_to_int('DS'),
                   dns_class_to_int(clas),
                   ttl,
                   len(rdata),
                   rdata, 0, 0)
        return L2_RR_DS.from_rr(rr)

    @staticmethod
    def from_rr(rr):
        keytag, algorithm, digest_type = unpack("! H B B",
                                                rr.rdata[0:4])
        digest = rr.rdata[4:]
        return L2_RR_DS(rr.name,
                        dns_class_to_str(rr.clas),
                        rr.ttl,
                        keytag,
                        dnssec_algorithm_to_str(algorithm),
                        dnssec_digest_type_to_str(digest_type),
                        digest)

    def canonical_l1(self, ttl):
        rdata = bytearray()
        rdata.extend(pack('! H B B',
                          self.keytag,
                          dnssec_algorithm_to_int(self.algorithm),
                          dnssec_digest_type_to_int(self.digest_type)))
        rdata.extend(self.digest)
        return DNSRR(self.name.lower(),
                     dns_type_to_int(self.typ),
                     dns_class_to_int('IN'),
                     ttl,
                     len(rdata),
                     rdata,
                     None,
                     None)

    def to_rr(self):
        b = bytearray()
        b.extend(pack('! H B B',
                      self.keytag,
                      dnssec_algorithm_to_int(self.algorithm),
                      dnssec_digest_type_to_int(self.digest_type)))
        b.extend(self.digest)
        return DNSRR(self.name,
                     dns_type_to_int(self.typ),
                     dns_class_to_int(self.clas),
                     self.ttl,
                     len(b),
                     b,
                     None,
                     None)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d IN %s %d %s %s %s' % (self.name,
                                            self.ttl,
                                            self.typ,
                                            self.keytag,
                                            self.algorithm,
                                            self.digest_type,
                                            binascii.hexlify(self.digest)
                                            .decode('ascii'))


def decode_type_bitmaps(rdata, offset):
    rr_types = []
    while offset < len(rdata):
        (window_block_number,
         bitmap_length) = unpack("! B B",
                                 rdata[offset:offset+2])
        dprint('window block #: %d, bitmap length: %d' %
               (window_block_number, bitmap_length))
        offset = offset + 2
        bitmap = rdata[offset:offset + bitmap_length]
        offset = offset + bitmap_length
        for bitmap_index in range(0, bitmap_length):
            bitmap_byte = bitmap[bitmap_index]
            dprint('bitmap_byte: %s' % format(bitmap_byte, '#010b'))
            for k in range(0, 8):
                # 7-k because it is in network order
                if (bitmap_byte & (1 << (7-k))) != 0:
                    rr_type = window_block_number * 256 + bitmap_index * 8 + k
                    rr_types.append(rr_type)
    return rr_types


class L2_RR_NSEC(namedtuple('L2_RR_NSEC', ['name',
                                           'clas',
                                           'ttl',
                                           'next_domain_name',
                                           'rr_types'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'NSEC'

    @staticmethod
    def from_rr(rr):
        next_domain_name, offset = decode_name(rr.rdata, 0)
        rr_types = decode_type_bitmaps(rr.rdata, offset)
        return L2_RR_NSEC(rr.name,
                          dns_class_to_str(rr.clas),
                          rr.ttl,
                          next_domain_name,
                          rr_types)

    def to_rr(self):
        pass

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        rr_types_as_str = map(dns_type_to_str, self.rr_types)
        return '%s %d IN %s %s %s' % (self.name,
                                      self.ttl,
                                      self.typ,
                                      self.next_domain_name,
                                      ' '.join(rr_types_as_str))


class L2_RR_NSEC3(namedtuple('L2_RR_NSEC3', ['name',
                                             'clas',
                                             'ttl',
                                             'algorithm',
                                             'flags',
                                             'opt_out',
                                             'iterations',
                                             'salt',
                                             'next_hashed_owner_name',
                                             'rr_types'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'NSEC3'

    @staticmethod
    def from_rr(rr):
        hash_algorithm, flags, iterations = unpack('! B B H', rr.rdata[0:4])
        offset = 4
        opt_out = ((flags & 0b1) == 0b1)
        salt_length, = unpack('! B', rr.rdata[offset:offset+1])
        offset = offset + 1
        salt = rr.rdata[offset:offset+salt_length]
        offset = offset + salt_length
        hash_length, = unpack('! B', rr.rdata[offset:offset+1])
        offset = offset + 1
        next_hashed_owner_name = rr.rdata[offset:offset+hash_length]
        offset = offset + hash_length
        rr_types = decode_type_bitmaps(rr.rdata, offset)
        return L2_RR_NSEC3(rr.name,
                           dns_class_to_str(rr.clas),
                           rr.ttl,
                           dnssec_nsec3_algorithm_to_str(hash_algorithm),
                           flags,
                           opt_out,
                           iterations,
                           salt,
                           next_hashed_owner_name,
                           sorted(rr_types))

    def to_rr(self):
        pass

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        rr_types_as_str = map(dns_type_to_str, self.rr_types)
        return ('%s %d %s %s' +
                '%s %d %d %s %s (%s)') % (self.name,
                                          self.ttl,
                                          self.clas,
                                          self.typ,
                                          self.algorithm,
                                          self.flags,
                                          self.iterations,
                                          binascii.hexlify(self.salt).
                                          decode('ascii').upper(),
                                          base64.b32encode(
                                              self.next_hashed_owner_name).
                                          decode('ascii'),
                                          ' '.join(rr_types_as_str))


class L2_RR_MX(namedtuple('L2_RR_MX', ['name',
                                       'clas',
                                       'ttl',
                                       'preference',
                                       'exchange'])):

    __slots__ = ()

    @property
    def typ(self):
        return 'MX'

    # RFC 1035 Section 3.3.9
    @staticmethod
    def from_presentation(name, ttl, clas, pa):
        preference = int(pa[0])
        exchange = pa[1]
        rdata = bytearray()
        rdata.extend(pack('! H',
                          preference))
        rdata.extend(encode_name(exchange))
        rr = DNSRR(name,
                   dns_type_to_int('MX'),
                   dns_class_to_int(clas),
                   ttl,
                   len(rdata),
                   rdata, 0, 0)
        return L2_RR_MX.from_rr(rr)

    # RFC 4034 Section 6.2
    def canonical_l1(self, ttl):
        rdata = bytearray()
        rdata.extend(pack('! H', self.preference))
        rdata.extend(encode_name(self.exchange))
        return DNSRR(self.name.lower(),
                     dns_type_to_int(self.typ),
                     dns_class_to_int('IN'),
                     ttl,
                     len(rdata),
                     rdata,
                     None,
                     None)

    @staticmethod
    def from_rr(rr):
        (preference, ) = unpack('! H', rr.rdata[0:2])
        exchange, _ = decode_name(rr.rdata[2:], 0)
        return L2_RR_MX(rr.name,
                        dns_class_to_str(rr.clas),
                        rr.ttl,
                        preference,
                        exchange)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return '%s %d %s %s %d %s' % (self.name,
                                      self.ttl,
                                      self.clas,
                                      self.typ,
                                      self.preference,
                                      self.exchange)
