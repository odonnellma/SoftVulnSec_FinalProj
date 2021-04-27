import oyaml as yaml
from scapy.all import *
from scapy.layers.inet import IP, TCP
import sys

tcp_tracker = {}

# Takes in a packet, checks if a RST was sent and data packets were sent after the RST
def tcp_reset_injection(pkt):
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
                    print_packet(pkt, "tcp_reset_injection")
                # if second packet is of the same connection tuple as first packet and the second packet is a TCP RST
                if key == key2 and 'R' in tcp_tracker[key][TCP].flags and tcp_tracker[key2][TCP].time > tcp_tracker[key][TCP].time:
                    print_packet(pkt, "tcp_reset_injection")

# Helper Function to extrapolate data from a given packet
def get_conn_tuple_tcp(pkt):
    return (pkt.src, pkt.sport, pkt.dst, pkt.dport)

def print_packet(pkt, attack_type: str):
    yaml_dump= {}
    yaml_dump['timestamp']= int(pkt.time)
    yaml_dump['source']= {'mac_address': pkt.hwsrc, 'ipv4_address': pkt.psrc, 'tcp_port': None}
    yaml_dump['target']= {'mac_address': pkt.hwdst, 'ipv4_address': pkt.pdst, 'tcp_port': None}
    yaml_dump['attack']= attack_type
    print(yaml.dump(yaml_dump)+'---')

def main():
    packets= rdpcap(sys.argv[1])
    print('Starting TCP RST injection detection\n')
    for pkt in packets:
        if 'TCP' in pkt:                                
            tcp_reset_injection(pkt)            # Check every TCP packet through algorithm
    print('Finished TCP RST injection detection\n')

if __name__ == "__main__":
    main()