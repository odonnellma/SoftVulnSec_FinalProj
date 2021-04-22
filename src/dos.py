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

score_keeper = {} # ip to time mapping
#syn_cache = ExpiringDict(max_len=256, max_age_seconds=60) # we can track up to 256 SYN records within a 10 second period
syn_cache = {}
block_list = [] # dictionary ip->AttackRecord mapping
timeout = Decimal(0.5)
backlog = 256 # we can tolerate 256 unanswered connections, really dependent on the functionality of the destination application
# record class containing detection information for one IP
class AttackRecord:

    def __init__(self, ip_address: tuple, port: tuple, str: time):
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
        if self.category == None:
            self.category = cat

# returns a dictionary containing the packet protocol/type, ip, port, and time seen
def get_basic_deets(packet) -> dict:
    collect = {}

    if packet.haslayer(IP): # attack within scope
        collect['time'] = packet.time
        iplayer = packet[IP]
        collect['ip'] = (iplayer.src, iplayer.dst)
        collect['protocol'] = iplayer.get_field('proto').i2s[iplayer.proto]

    if packet.haslayer(TCP): #syn flood possible
        tcplayer = packet[TCP]
        collect['port'] = (tcplayer.sport, tcplayer.dport)
    elif packet.haslayer[UDP]: #udp flood possible
        udplayer = packet[UDP]
        collect['port'] = (udplayer.sport, udplayer.dport)
    elif packet.haslayer[ICMP]: # icmp ping flood possible
        if packet.haslayer[UDPerror]:
            udpinicmplayer = packet[UDPerror]
            collect['port'] = (udpinicmplayer.sport, udpinicmplayer.dport)
        else:
            collect['port'] = ('','') #no port is fine

    return collect

# return true if packet exhibits behavior of udp flood
def check_udp(packet, details) -> bool:
    return False

# return true if packet exhibits behavior of icmp (ping) flood
def check_icmp(packet, details) -> bool:
    return False

# return true if packet exhibits behavior of syn flood 
# for a src ip, if this is a SYN packet, check that we've
# received an ACK back (if we send a SYN-ACK) within timeout
# tolerate a consistent 20% success rate
i = 0
def check_syn(packet, details) -> bool:
    global i
    tcplayer = packet[TCP]
    if tcplayer.flags == 'S': # SYN from outside
        if details['ip'][0] in syn_cache: # if already exists, check time constraints
            time = details['time'] # we'll keep on updating the oldest things in the cache
            sport = details['port'][0]
            record = syn_cache[details['ip'][0]]
            cached_port = next(iter(record['time_port']))
            oldest = record['time_port'][cached_port]
            # later see if you can do a range of oldest times and take percentage of that
            if time - oldest >= timeout and record['acks']/record['syns'] < 0.2:
                record['count'] += 1
            # still want to store this entry
            record['time_port'][sport] = time
            record['syns'] += 1
            # check for three strikes
            if record['count'] == 3:
                return True

        else: # first SYN from this src ip to dest ip
            syn_cache[details['ip'][0]] = { "time_port": {details['port'][0]: details['time']},
                                            "syns": 1,
                                            "acks": 0,
                                            "count": 0
                                        }
    elif tcplayer.flags == 'A': # no questions asked, we'll take it
        sport = details['port'][0]
        record = syn_cache[details['ip'][0]]
        if sport in record:
            record.pop(sport)
            record['acks'] += 1

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
    if p_details['ip'][0] in block_list:
        block_list[p_details['ip'][0]].happened_again(p_details['time'])
        block_list[p_details['ip'][0]].add_port(p_details['port'])
    else:
        placeholder = AttackRecord(p_details['ip'], p_details['port'], p_details['time'])
        if p_details['protocol'] == 'udp':
            if check_udp(packet, p_details):
                placeholder.set_category('UDP Flood')
                block_list.append({p_details['ip']: (placeholder, placeholder.category)})
        if p_details['protocol'] == 'icmp':
            if check_icmp(packet, p_details):
                placeholder.set_category('ICMP (Ping) Flood')
                block_list.append({p_details['ip']: (placeholder, placeholder.category)})
        elif p_details['protocol'] == 'tcp':
            if check_syn(packet, p_details):
                placeholder.set_category('SYN Flood')
                block_list.append({p_details['ip']: (placeholder, placeholder.category)})

print(block_list)
