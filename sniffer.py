import socket
import struct

class IPHeader:
    def __init__(self, raw_data):
        ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data)
        self.protocol = ip_header[6]
        self.source_ip = socket.inet_ntoa(ip_header[8])
        self.destination_ip = socket.inet_ntoa(ip_header[9])

def conn():
    # Create a raw socket and bind it to the network interface
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind(("192.168.90.14", 0))
    # Include IP headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Enable promiscuous mode
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return sniffer

def main():
    sniffer = conn()
    print("Sniffer Started:")
    # Sniff packets
    sniff(sniffer)

def sniff(conn):
    while True:
        # Receive packet
        raw_data, _ = conn.recvfrom(65536)
        # Extract Ethernet header (first 14 bytes)
        eth_header = raw_data[:14]
        # Unpack Ethernet header
        dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', eth_header)
        # Print MAC addresses and Ethernet protocol
        print(f"Source MAC: {get_mac_address(src_mac)} Destination MAC: {get_mac_address(dest_mac)} EtherType: {eth_proto}")

def get_mac_address(mac):
    return ":".join("{:02x}".format(b) for b in mac)

if __name__ == '__main__':
    main()
