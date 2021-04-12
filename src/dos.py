# isolates ip addresses exhibiting indicators of DoS
# permanent block demonstrated on offline traffic is the equivalent of skipping over packets from that ip when parsing
# behavior-tracking revolves around some timeout t
# Outputs DoS report information

# DOS attacks to handle:
# UDP/ICMP floods
# SYN Floods
# Does not handle:
# Ping of Death (out of scope)
# HTTP Flood (out of scope)
# Slowloris
# False positives to avoid:
# Fragmented TCP/IP packets 
# If fragments, must receive within some window otherwise classified as attack behavior

# UDP:
# Same server IP, different client ports
# ICMP:
# Pings should be disabled in the first place
# Put server on warning list, check traffic for more sus behavior from server within t
# TCP/SYN:
# No ACK, or inordinary number of SYNs from different IPs within t

from scapy.all import *
from expiringdict import ExpiringDict
import sys

score_keeper = {}
cache = ExpiringDict(max_len=100, max_age_seconds=10)
block_list = [] # dictionary ip->AttackRecord mapping

# record class containing detection information for one IP
class AttackRecord:

    def __init__(self, ip_address: str, port: int, str: time):
        self.ip = ip_address
        self.ports = [port]
        self.timestamps = [time]
        self.occurences = 1
        self.category = None

    # add port if not seen before
    def add_port(self, port: int):
        if not port in self.ports:
            self.ports.append(port)

    # add another timestamp and increment number of detections
    # could alternatively just query for size of timestamps list
    # but this is fine
    def happened_again(self, time: str):
        self.timestamps.append(time)
        self.occurences += 1

    def set_category(self, cat: str):
        if self.category != None:
            self.category = cat

# returns a dictionary containing the packet protocol/type, ip, port, and time seen
def get_basic_deets(packet) -> dict:
    collect = {}
    return collect

# return true if packet exhibits behavior of udp flood
def check_udp(packet) -> bool:
    return False

# return true if packet exhibits behavior of icmp (ping) flood
def check_icmp(packet) -> bool:
    return False

# return true if packet exhibits behavior of syn flood 
def check_syn(packet) -> bool:
    return False

# input path to PCAP to get packets as list
pcap = PcapReader(sys.argv[1])
#i = 1

# run analysis over pcap
for packet in pcap:
    #if i == 523 or i == 524:
    #    packet.show()
    #i += 1

    p_details = get_basic_deets(packet) # {ip, protocol, port, timestamp}
    if p_details['ip'] in block_list:
        block_list[p_details['ip']].happened_again(p_details['time'])
        block_list[p_details['ip']].add_port(p_details['port'])
    else:
        placeholder = AttackRecord(p_details['ip'], p_details['port'], p_details['timestamp'])
        if p_details['protocol'] == 'udp':
            if check_udp(packet):
                block_list.append({p_details['ip']:placeholder.set_category('UDP Flood')})
            elif check_icmp(packet):
                block_list.append({p_details['ip']:placeholder.set_category('ICMP (Ping) Flood')})
        elif p_details['protocol'] == 'tcp':
            if check_syn(packet):
                block_list.append({p_details['ip']:placeholder.set_category('SYN Flood')})

sys.stdout(block_list)
