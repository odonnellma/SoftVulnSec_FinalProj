import oyaml as yaml
from scapy.all import *
from scapy.layers.inet import IP, TCP
import sys

arp_tracker = {}
tcp_tracker = {}

# Takes in a packet, checks if that 
def arp_cache_poisoning(pkt):
    yaml_dump= {}
    if pkt.psrc in arp_tracker and pkt.hwsrc != arp_tracker[pkt.psrc]:          # In ARP, the pkt.hwsrc is used to denote the address that was being looked for
        yaml_dump['timestamp']= int(pkt.time)
        yaml_dump['source']= {'mac_address': pkt.hwsrc, 'ipv4_address': pkt.psrc, 'tcp_port': None}
        yaml_dump['target']= {'mac_address': pkt.hwdst, 'ipv4_address': pkt.pdst, 'tcp_port': None}
        yaml_dump['attack']= 'arp_cache_poisoning'
        print(yaml.dump(yaml_dump)+'---')
    elif pkt.psrc not in arp_tracker.keys():
        for ip in arp_tracker.keys():
            if arp_tracker[ip] == pkt.hwsrc:
                yaml_dump['timestamp']= int(pkt.time)
                yaml_dump['source']= {'mac_address': pkt.hwsrc, 'ipv4_address': pkt.psrc, 'tcp_port': None}
                yaml_dump['target']= {'mac_address': pkt.hwdst, 'ipv4_address': pkt.pdst, 'tcp_port': None}
                yaml_dump['attack']= 'arp_cache_poisoning'
                print(yaml.dump(yaml_dump)+'---')
    arp_tracker[pkt.psrc]= pkt.hwsrc

def tcp_reset_injection(pkt):
    yaml_dump= {}
    # Looking for more packets sent by an endpoint AFTER a RST is sent or a RST packet with a lower SEQ than other data packets
    # out of order seq numbers?
    tcp_tracker[get_conn_tuple_tcp(pkt)] = pkt

    t_stamp= pkt[TCP].time
    # sliding window, expire old packets
    # connection tuple as keys, packet as value
    for key in list(tcp_tracker.keys()):
        if tcp_tracker[key][TCP].time < t_stamp-.2: # Purge old packets
            tcp_tracker.pop(key)

    for key in tcp_tracker:
        if 'R' in tcp_tracker[key][TCP].flags:
            comp_packet= tcp_tracker[key]
            for key2 in tcp_tracker:
                if key == key2 and 'R' not in tcp_tracker[key][TCP].flags and tcp_tracker[key2][TCP].time > tcp_tracker[key][TCP].time:
                    yaml_dump['timestamp']= int(tcp_tracker[key2][TCP].time)
                    yaml_dump['source']= {'mac_address': tcp_tracker[key2].src, 'ipv4_address': tcp_tracker[key2][IP].src, 'tcp_port': tcp_tracker[key2][TCP].sport}
                    yaml_dump['target']= {'mac_address': tcp_tracker[key2].dst, 'ipv4_address': tcp_tracker[key2][IP].dst, 'tcp_port': tcp_tracker[key2][TCP].dport}
                    yaml_dump['attack']= 'tcp_reset_injection'
                    print(yaml.dump(yaml_dump)+'---')

                # if second packet is of the same connection tuple as first packet and the second packet is a TCP RST
                if key == key2 and 'R' in tcp_tracker[key][TCP].flags and tcp_tracker[key2][TCP].time > tcp_tracker[key][TCP].time:
                    yaml_dump['timestamp']= int(tcp_tracker[key2][TCP].time)
                    yaml_dump['source']= {'mac_address': tcp_tracker[key2].src, 'ipv4_address': tcp_tracker[key2][IP].src, 'tcp_port': tcp_tracker[key2][TCP].sport}
                    yaml_dump['target']= {'mac_address': tcp_tracker[key2].dst, 'ipv4_address': tcp_tracker[key2][IP].dst, 'tcp_port': tcp_tracker[key2][TCP].dport}
                    yaml_dump['attack']= 'tcp_reset_injection'
                    print(yaml.dump(yaml_dump)+'---')


def get_conn_tuple_tcp(pkt):
    return (pkt.src, pkt.sport, pkt.dst, pkt.dport)

def main():
    packets= rdpcap(sys.argv[1])

    for pkt in packets:
        if 'ARP' in pkt and pkt.op == 2:        # Get only 'is-at' packets that are ARP protocol
            arp_cache_poisoning(pkt)
        #if 'TCP' in pkt:                                
        #    tcp_reset_injection(pkt)            # Check every TCP packet through algorithm

if __name__ == "__main__":
    main()