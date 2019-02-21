import socket
import binascii
from digsec import dprint


# send the raw dns req and return the raw response
def send_recv(req, ns="8.8.8.8", port=53, udp=True):
    dprint("----- START NETWORK COMMUNICATION -----")
    sendaddress = (ns, port)
    dprint('Sending %d bytes to %s' % (len(req), sendaddress))
    dprint('0x%s' % binascii.hexlify(req).decode('ascii'))
    if udp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 4242))  # 4242 just a random port number
        sock.sendto(req, sendaddress)
        (res, resaddress) = sock.recvfrom(4096)
    else:
        pass
    dprint('Received %d bytes from %s' % (len(res), resaddress))
    dprint('0x%s' % binascii.hexlify(res).decode('ascii'))
    dprint("----- END NETWORK COMMUNICATION -----")
    return res
