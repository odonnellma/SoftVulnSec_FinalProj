import oyaml as yaml
from scapy.all import *
from scapy.layers.inet import IP, TCP
import sys

arp_tracker = {}

# Takes in a packet, checks if that IP/ MAC Address has been previously mapped
def arp_cache_poisoning(pkt):
    if pkt.psrc in arp_tracker and pkt.hwsrc != arp_tracker[pkt.psrc]:          # In ARP, the pkt.hwsrc is used to denote the address that was being looked for
        print_packet(pkt, "arp_cache_poisoning")
    elif pkt.psrc not in arp_tracker.keys():
        for ip in arp_tracker.keys():
            if arp_tracker[ip] == pkt.hwsrc:
                print_packet(pkt, "arp_cache_poisoning")
    arp_tracker[pkt.psrc]= pkt.hwsrc

def print_packet(pkt, attack_type: str):
    yaml_dump= {}
    yaml_dump['timestamp']= int(pkt.time)
    yaml_dump['source']= {'mac_address': pkt.hwsrc, 'ipv4_address': pkt.psrc, 'tcp_port': None}
    yaml_dump['target']= {'mac_address': pkt.hwdst, 'ipv4_address': pkt.pdst, 'tcp_port': None}
    yaml_dump['attack']= attack_type
    print(yaml.dump(yaml_dump)+'---')

def main():
    packets= rdpcap(sys.argv[1])
    print('Starting ARP cache poisoning detection\n')
    for pkt in packets:
        if 'ARP' in pkt and pkt.op == 2:        # Get only 'is-at' packets that are ARP protocol
            arp_cache_poisoning(pkt)
    print('Finished ARP cache poisoning detection\n')


if __name__ == "__main__":
    main()