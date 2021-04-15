from scapy.all import *
from scapy.layers.inet import IP, TCP
import sys
import pprint

arp_tracker = {}

def arp_cache_poisoning(pkt):
    if pkt.psrc in arp_tracker and pkt.hwsrc != arp_tracker[pkt.psrc]:      # In ARP, the pkt.hwsrc is used to denote the address that was being looked for
        print("timestamp: %i"%pkt.time)                                     # Timestamp
        print("source:")
        print("\tmac_address: %s"%pkt.hwsrc)
        print("\tipv4_address: %s"%pkt.psrc)
        print("\ttcp_port: null")
        print("target:")
        print("\tmac_address: %s"%pkt.hwdst)
        print("\tipv4_address: %s"%pkt.pdst)
        print("\ttcp_port: null")
        print("attack: arp_cache_poisoning")
        arp_tracker[pkt.psrc]= pkt.hwsrc
    else:
        arp_tracker[pkt.psrc]= pkt.hwsrc
        #print(arp_tracker)
    return

def main():
    global packet_size
    global id1
    packet_size = 0
    id1 = -1

    packets= rdpcap('/path/to/pcap')

    for pkt in packets:
        if 'ARP' in pkt and pkt.op == 2:                # Get only 'is-at' packets that are ARP protocol
            arp_cache_poisoning(pkt)
    
if __name__ == "__main__":
    main()