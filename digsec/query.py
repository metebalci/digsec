# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
handles query command
"""
import os
from digsec import DigsecError
from digsec.messages import DNSMessage, DNSHeader, DNSFlags
from digsec.messages import DNSQuestionRR, DNSOptRR
from digsec.utils import dprint, parse_flags
from digsec.utils import random_dns_message_id
from digsec.utils import dns_type_to_int, dns_class_to_int
from digsec.answer import save_section
from digsec.help import display_help_query
from digsec.comm import send_recv


# pylint: disable=too-many-arguments
# decision of including OPT is by udp_payload_size, since it is a must in OPT
def __make_query_message(qname,
                         qtype,
                         qclass,
                         rd,
                         cd,
                         udp_payload_size,
                         dnssec_ok=False):
    msgid = random_dns_message_id()
    qrr = DNSQuestionRR(qname,
                        dns_type_to_int(qtype),
                        dns_class_to_int(qclass))
    if udp_payload_size is not None:
        opt_rr = DNSOptRR(udp_payload_size,
                          0,
                          0,
                          dnssec_ok,
                          [])
    else:
        opt_rr = None
    dns_message = DNSMessage(DNSHeader(msgid,
                                       DNSFlags(False,
                                                0,
                                                False,
                                                False,
                                                rd,
                                                False,
                                                False,
                                                cd,
                                                0),
                                       1,
                                       0,
                                       0,
                                       1 if opt_rr else 0),
                             [qrr],
                             [],
                             [],
                             [opt_rr] if opt_rr is not None else [])
    return dns_message


def query(server, port, qname, qtype, qclass, flags):
    """
    Makes a DNS query

    qname --
    qtype --
    qclass --
    flags -- rd, cd, udp_payload_size, do used
    """

    dns_query_message = __make_query_message(qname,
                                             qtype,
                                             qclass,
                                             flags['rd'],
                                             flags['cd'],
                                             flags['udp_payload_size'],
                                             flags['do'])

    dns_query_packet = dns_query_message.to_packet()

    dprint('<<< NETWORK COMMUNICATION >>>')
    dprint('Server: %s:%s/%d' % (server,
                                 'tcp' if flags['tcp'] else 'udp', port))
    dprint()

    dns_response_packet = send_recv(dns_query_packet,
                                    server,
                                    port,
                                    flags)

    if dns_response_packet is None:
        return (dns_query_message,
                dns_query_packet,
                None,
                None)

    dns_response_message = DNSMessage.from_packet(dns_response_packet)

    return (dns_query_message,
            dns_query_packet,
            dns_response_packet,
            dns_response_message)


# pylint: disable=too-many-locals
# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
def do_query(argv):
    non_plus_and_at = list(filter(lambda x: x[0] != '+', argv))
    non_plus = list(filter(lambda x: x[0] != '@', non_plus_and_at))
    dprint('non_plus:')
    dprint(non_plus)
    at = list(filter(lambda x: x[0] == '@', argv))
    dprint('at')
    dprint(at)
    if len(non_plus) == 0:
        display_help_query()
    elif len(non_plus) == 1:
        qname = non_plus[0]
        qtype = 'A'
        qclass = 'IN'
    elif len(non_plus) == 2:
        qname = non_plus[0]
        qtype = non_plus[1]
        qclass = 'IN'
    elif len(non_plus) == 3:
        qname = non_plus[0]
        qtype = non_plus[1]
        qclass = non_plus[2]
    else:
        raise DigsecError('Too many arguments, see usage')
    # requests for root need empty qname
    if qname == '.':
        qname = ''
    # ignore last dot
    if qname.endswith('.'):
        qname = qname[:-1]
    default_flags = {'rd': False,
                     'cd': False,
                     'do': False,
                     'udp_payload_size': None,
                     'tcp': False,
                     'timeout': None,
                     'show-protocol': False,
                     'save-answer': False,
                     'save-answer-prefix': None,
                     'save-answer-dir': None,
                     'save-packets': None,
                     'show-friendly': False}
    flags = parse_flags(argv, default_flags)
    dprint(flags)

    if flags['do'] and (flags['udp_payload_size'] is None):
        raise DigsecError('+do requires +udp_payload_size=<size>')

    save_answer = flags['save-answer']
    show_protocol = flags['show-protocol']
    save_packets = flags['save-packets']
    save_answer_prefix = flags['save-answer-prefix']
    save_answer_dir = flags['save-answer-dir']
    show_friendly = flags['show-friendly']

    if save_answer:
        if save_answer_prefix is None:
            save_answer_prefix = ''
        # if not given, save to current working dir
        if save_answer_dir is None:
            save_answer_dir = os.getcwd()
        else:
            # if given and it is a relative path, save to current wc + given
            if not os.path.isabs(save_answer_dir):
                save_answer_dir = os.path.join(os.getcwd(), save_answer_dir)
        if not os.path.exists(save_answer_dir):
            raise DigsecError('save-answer-path: "%s" does not exist' %
                              save_answer_dir)
    else:
        show_friendly = True

    if len(at) > 0:
        server_and_port = at[0][1:].split(':')
        if len(server_and_port) == 1:
            server = server_and_port[0]
            port = 53
        else:
            server = server_and_port[0]
            port = int(server_and_port[1])
    else:
        server = '1.1.1.1'
        port = 53
    dprint('server:port = %s:%d' % (server, port))

    (dns_query_message,
     dns_query_packet,
     dns_response_packet,
     dns_response_message) = query(server,
                                   port,
                                   qname,
                                   qtype,
                                   qclass,
                                   flags)

    if show_protocol:
        print('<<< Protocol Query >>>')
        print()
        print(dns_query_message)
        print()

    if show_friendly:
        print('<<< Friendly Query >>>')
        print()
        print(dns_query_message.l2())
        print()

    if save_packets:
        with open('%s.q' % save_packets, 'wb') as f:
            f.write(dns_query_packet)

    if show_protocol or show_friendly:
        print('<<< NETWORK COMMUNICATION >>>')
        print('Server: %s:%s/%d' % (server,
                                    'tcp' if flags['tcp'] else 'udp', port))
        print()

    dns_response_packet = send_recv(dns_query_packet,
                                    server,
                                    port,
                                    flags)

    if dns_response_packet is None:
        return

    if save_packets:
        with open('%s.r' % save_packets, 'wb') as f:
            f.write(dns_response_packet)

    dns_response_message = DNSMessage.from_packet(dns_response_packet)

    if show_protocol:
        print('<<< Protocol Response >>>')
        print()
        print(dns_response_message)
        print()

    if show_friendly:
        print('<<< Friendly Response >>>')
        print()
        print(dns_response_message.l2())
        print()

    if save_answer:
        filename_prefix = '%s%s.%s' % (save_answer_prefix,
                                       qname if len(qname) > 0 else '_root',
                                       qclass)
        dprint('save_answer_dir: %s, filename_prefix: %s' % (save_answer_dir,
                                                             filename_prefix))
        save_section(save_answer_dir,
                     filename_prefix,
                     dns_response_message.answer)
