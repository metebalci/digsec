import os
from digsec.messages import DNSMessage, DNSHeader, DNSFlags
from digsec.messages import DNSQuestionRR, DNSOptRR
from digsec.utils import dprint, error, parse_flags
from digsec.utils import random_dns_message_id
from digsec.utils import dns_type_to_int, dns_class_to_int
from digsec.answer import save_rrset
from digsec.help import display_help_query
from digsec.comm import send_recv


# decision of including OPT is by udp_payload_size, since it is a must in OPT
def make_query_message(qname,
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


def do_query(argv):
    non_plus = list(filter(lambda x: x[0] != '+', argv))
    dprint(non_plus)
    if len(non_plus) == 0:
        error('Missing arguments')
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
        error('Too many arguments, see usage')
    # requests for root need empty qname
    if qname == '.':
        qname == ''
    # ignore last dot
    if qname.endswith('.'):
        qname = qname[:-1]
    default_flags = {'rd': False,
                     'cd': False,
                     'do': False,
                     'udp_payload_size': None,
                     'save-answer': None,
                     'save-answer-dir': os.getcwd(),
                     'show-protocol': False,
                     'save-packets': None,
                     'show-friendly': True}
    flags = parse_flags(argv, default_flags)
    dprint(flags)

    if flags['do'] and (flags['udp_payload_size'] is None):
        error('+do requires +udp_payload_size=<size>')

    show_protocol = flags['show-protocol']
    save_packets = flags['save-packets']
    save_answer = flags['save-answer']
    save_answer_dir = flags['save-answer-dir']
    show_friendly = flags['show-friendly']

    dns_query = make_query_message(qname,
                                   qtype,
                                   qclass,
                                   flags['rd'],
                                   flags['cd'],
                                   flags['udp_payload_size'],
                                   flags['do'])

    if show_protocol:
        print('<<< Protocol Query >>>')
        print()
        print(dns_query)
        print()

    dns_query_packet = dns_query.to_packet()

    if show_friendly:
        print('<<< Friendly Query >>>')
        print()
        print(dns_query.l2())
        print()

    if save_packets:
        with open('%s.q' % save_packets, 'wb') as f:
            f.write(dns_query_packet)

    if show_protocol or show_friendly:
        print('<<< NETWORK COMMUNICATION >>>')
        print()

    dns_response_packet = send_recv(dns_query_packet)

    if save_packets:
        with open('%s.r' % save_packets, 'wb') as f:
            f.write(dns_response_packet)

    dns_response_message = DNSMessage.from_packet(dns_response_packet)

    if show_protocol:
        print('<<< Protocol Response >>>')
        print()
        print(dns_response_message)
        print()

    # it can be '' and this means False if used alone in if
    if save_answer is not None:
        filename_prefix = '%s%s.%s' % (save_answer,
                                       qname if len(qname) > 0 else '_root',
                                       qclass)
        save_rrset(save_answer_dir,
                   filename_prefix,
                   dns_response_message.answer)

    if show_friendly:
        print('<<< Friendly Response >>>')
        print()
        print(dns_response_message.l2())
        print()
