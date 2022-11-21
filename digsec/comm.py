# coding: utf-8
# pylint: disable=missing-function-docstring
"""
handles network/socket communication with DNS servers
"""
import binascii
import socket
from struct import pack, unpack
from digsec import dprint


# send the raw dns req and return the raw response
def send_recv(req, addr, port, flags):
    timeout = flags['timeout']
    tcp = flags['tcp']
    dprint("----- START (%s) NETWORK COMMUNICATION -----" %
           ("TCP" if tcp else "UDP",))
    sendaddress = (addr, port)
    dprint('Sending %d bytes to %s:%s/%d' %
           (len(req), sendaddress[0], 'tcp' if tcp else 'udp', sendaddress[1]))
    dprint('0x%s' % binascii.hexlify(req).decode('ascii'))
    try:
        if tcp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(sendaddress)
            # with tcp, first the size of packet (2 bytes) is sent
            data_to_send = bytearray()
            data_to_send.extend(pack('! H', len(req)))
            data_to_send.extend(req)
            dprint('actual TCP data: 0x%s' %
                   binascii.hexlify(data_to_send).decode('ascii'))
            sock.sendall(data_to_send)
            # with tcp, first the size of packet (2 bytes) is returned
            tcp_res_len = sock.recv(2)
            (res_len,) = unpack('! H', tcp_res_len)
            dprint('Received len=%d with TCP' % res_len)
            res = sock.recv(res_len)
            dprint('0x%s' % binascii.hexlify(res).decode('ascii'))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if timeout is not None:
                sock.settimeout(timeout)
            sock.bind(('', 0)) # 0 selects a free port
            sock.sendto(req, sendaddress)
            (res, resaddress) = sock.recvfrom(4096)
            dprint('Received %d bytes from %s with UDP' % (len(res), resaddress))
            dprint('0x%s' % binascii.hexlify(res).decode('ascii'))
    except socket.timeout:
        print('Error: Timeout when waiting for the response.')
        res = None
    dprint("----- END (%s) NETWORK COMMUNICATION -----" % ("TCP" if tcp else "UDP",))
    return res
