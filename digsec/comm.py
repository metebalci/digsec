import socket
import binascii
from digsec import dprint


# send the raw dns req and return the raw response
def send_recv(req, addr, port, timeout):
    dprint("----- START NETWORK COMMUNICATION -----")
    sendaddress = (addr, port)
    dprint('Sending %d bytes to %s' % (len(req), sendaddress))
    dprint('0x%s' % binascii.hexlify(req).decode('ascii'))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 4242))  # 4242 just a random port number
    sock.sendto(req, sendaddress)
    try:
        sock.settimeout(timeout)
        (res, resaddress) = sock.recvfrom(4096)
        dprint('Received %d bytes from %s' % (len(res), resaddress))
        dprint('0x%s' % binascii.hexlify(res).decode('ascii'))
    except socket.timeout:
        print('Error: Timeout when waiting for the response.')
        res = None
    dprint("----- END NETWORK COMMUNICATION -----")
    return res
