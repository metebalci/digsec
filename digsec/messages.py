from struct import pack, unpack
from collections import namedtuple
import binascii
from datetime import datetime
import base64
from digsec import dprint
from digsec.utils import l2s, dns_class_to_int, dns_type_to_int
from digsec.utils import dns_opcode_to_str, dns_rcode_to_str
from digsec.utils import dns_class_to_str, dns_type_to_str
from digsec.utils import dnssec_algorithm_to_int, dnssec_algorithm_to_str
from digsec.utils import dnssec_digest_type_to_int, dnssec_digest_type_to_str
from digsec.utils import decode_name, encode_name, calculate_keytag
from digsec.utils import dnssec_nsec3_algorithm_to_str


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
            for i in range(0, count):
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
        if self.qr:
            fs.append('QR')
        else:
            fs.append('__')
        fs.append('%04X' % self.opcode)
        if self.aa:
            fs.append('AA')
        else:
            fs.append('__')
        if self.tc:
            fs.append('TC')
        else:
            fs.append('__')
        if self.rd:
            fs.append('RD')
        else:
            fs.append('__')
        if self.ra:
            fs.append('RA')
        else:
            fs.append('__')
        if self.ad:
            fs.append('AD')
        else:
            fs.append('__')
        if self.cd:
            fs.append('CD')
        else:
            fs.append('__')
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
        return (DNSRR(name,
                      typ,
                      clas,
                      ttl,
                      rdlength,
                      rdata,
                      packet,
                      offset + 10),
                offset + 10 + rdlength)

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

    @staticmethod
    def from_packet(packet, offset):
        (name,
         typ,
         udp_payload_size,
         extended_rcode,
         version,
         DO,
         Z,
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
        opts.append('\tOptions: %s' % ','.join(self.options))
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


def decode_type_bitmaps(rdata, offset):
    rr_types = list()
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
