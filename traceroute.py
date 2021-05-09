import sys
from scapy.all import Ether
from scapy.all import IP
from scapy.all import ICMP
from scapy.all import srp1
from scapy.all import conf


"""
notes:
"""
#MAC address of the GW
MAC_ADDRESS="d8:07:b6:26:0e:73"
ICMP_TIMEOUT_CODE = 11
ICMP_ECHO_CODE = 0


def csr_pkt(address, ttl):
    """Create send to the wire and receive packet
    :param address: ip or dns address of the destination.
    :param ttl: TimeToLive of the current packet sent to wire.
    :type address: str
    :type ttl: int
    :return: icmp respond.
    :rtype: scapy.packet
    """
    pkt = Ether(dst=MAC_ADDRESS)/IP(dst=address, ttl=ttl)/ICMP()
    response = srp1(pkt, iface=conf.iface, verbose=False, timeout=1)
    return response


def icmp(address, ttl):
    """Generate icmp packet and gathering icmp relevant info for producing viable traceroute from the received icmp.
        :param address: ip or dns address of the destination.
        :param ttl: the maximum hops for the traceroute func to go through.
        :type address: str
        :type ttl: int
        :return: tuple with (str, int, int), (hop_ip_address, icmp_code, icmp_type)
        :rtype: tuple
    """
    response = csr_pkt(address, ttl)

    if response is not None:
        hop_ip_address = response[IP].src
        icmp_code = response[ICMP].code
        icmp_type = response[ICMP].type
    elif response is None:
        hop_ip_address = "Request timed out."
        icmp_code = 0
        icmp_type = 0
    return hop_ip_address, icmp_code, icmp_type


def trace_route(address, ttl):
    """"Discover the ip route path to address of destination and prints the path as text.
        :param address: ip or dns address of the destination.
        :param ttl: the maximum hops for the traceroute func to go through.
        :type address: str
        :type ttl: int
        :return: None
    """
    for i in range(1, ttl + 1):
        hop_ip_address, icmp_code, icmp_type = icmp(address, i)

        if icmp_code == ICMP_ECHO_CODE and icmp_type == ICMP_TIMEOUT_CODE:
            print("Hop #%s IP address %s" % (i, hop_ip_address))
        elif hop_ip_address == "Request timed out.":
            print("Hop #%s %s, sorry couldn't get this one for you" % (i, hop_ip_address))
        elif hop_ip_address == address:
            print("Hop #%s IP address %s and final" % (i, hop_ip_address))
            break
    print("\nTrace Route Complete")

def main():
    address = sys.argv[1] #input("please provide ip address: ")
    ttl = sys.argv[2] #input("please provide ttl: ")
    trace_route(address, int(ttl))


if __name__ == "__main__":
    main()
