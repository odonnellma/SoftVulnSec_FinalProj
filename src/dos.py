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
import oyaml as yaml
import sys

score_keeper = {} # ip to time mapping
#syn_cache = ExpiringDict(max_len=256, max_age_seconds=60) # we can track up to 256 SYN records within a 10 second period
syn_cache = {}
icmp_cache = {}
udp_cache = {}
block_list = {} # dictionary ip->AttackRecord mapping
timeout = Decimal(0.5)
backlog = 5
limit = 3
allowed_ports = [53, 67, 68, 69, 123, 137, 138, 139, 161, 162, 389, 636]
#allowed_ports = ['53', '67', '68', '69', '123', '137', '138', '139', '161', '162', '389', '636']
# record class containing detection information for one IP
class AttackRecord:

    def __init__(self, mac: tuple, ip_address: tuple, port: tuple, time: str):
        self.mac = mac
        self.ip = ip_address
        self.ports = [port]
        self.timestamps = [time]
        self.occurences = 1
        self.category = None

    # add port if not seen before
    def add_port(self, port: int):
        if not port in self.ports: # specific src-target tuple
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
    def all_unique_ports(self, i: int):
        temp = []
        for p in self.ports:
            temp.append(p[i])
        return list(set(temp))

# returns a dictionary containing the packet protocol/type, ip, port, and time seen
def get_basic_deets(packet) -> dict:
    collect = {}

    if packet.haslayer(Ether): # definitely should have but still check
        maclayer = packet[Ether]
        collect['mac'] = (maclayer.src, maclayer.dst)
    else:
        collect['mac'] = ('', '') # fine but literally how
    if packet.haslayer(IP): # attack within scope
        collect['time'] = packet.time
        iplayer = packet[IP]
        collect['ip'] = (iplayer.src, iplayer.dst)
        collect['protocol'] = iplayer.get_field('proto').i2s[iplayer.proto]
    else: # nope
        collect['ip'] = ('','')
    if packet.haslayer(TCP): #syn flood possible
        tcplayer = packet[TCP]
        collect['port'] = (tcplayer.sport, tcplayer.dport)
    elif packet.haslayer(UDP): #udp flood possible, but also filter out DNS
        udplayer = packet[UDP]
        collect['port'] = (udplayer.sport, udplayer.dport)
        #if packet.haslayer(DNS):
        #    collect['protocol'] = 'dns'
    elif packet.haslayer(ICMP): # icmp ping flood possible
        if packet.haslayer(UDPerror):
            udpinicmplayer = packet[UDPerror]
            collect['port'] = (udpinicmplayer.sport, udpinicmplayer.dport)
        else:
            icmplayer = packet[ICMP]
            collect['port'] = (icmplayer.id, icmplayer.id) #no port is fine, get ICMP id instea
    return collect

# return true if packet exhibits behavior of udp flood
def check_udp(packet, details) -> bool:
    if details['port'][0] not in allowed_ports and details['port'][1] not in allowed_ports: # valid udp traffic should not be checked, for instance port 53 for DNS queries/responses
        udplayer = packet[UDP]
        if details['ip'][0] in udp_cache:
            time = details['time']
            sport = details['port'][0]
            record = udp_cache[details['ip'][0]]
            recent_key = list(record['time_port'].keys())[-1]
            recent = record['time_port'][recent_key]
            if time - recent <= timeout:
                record['count'] += 1
            record['time_port'][sport] = time
            if record["count"] >= limit:
                return True
        else:
            udp_cache[details['ip'][0]] = { "time_port": {details['port'][0]: details['time']},
                                        "count": 1}
    return False

def check_icmp_cache(srcip) -> bool:
    result = False
    cached_record = icmp_cache[srcip]['sourceid_count']
    sources_for_ip = list(cached_record.keys())
    if len(sources_for_ip) > backlog:
        results = True
    else:
        for key in sources_for_ip:
            if cached_record[key] >= limit:
                result = True
                break
    return result

# return true if packet exhibits behavior of icmp (ping) flood
def check_icmp(packet, details) -> bool:
    if packet[ICMP].get_field('type').i2s[packet[ICMP].type] == 'echo-request': # ping type
        if details['ip'][0] in icmp_cache: # if already exists, we check the dictionary of different source ports
            time = details['time']
            id_or_sport = details['port'][0]
            record = icmp_cache[details['ip'][0]]
            if id_or_sport in record['sourceid_count']:
                record['sourceid_count'][id_or_sport] += 1
            else:
                record['sourceid_count'][id_or_sport] = 1
            # needs to check if size of sourceid_count is over limit(num sports), or count of at least one sport is over limit
            return check_icmp_cache(details['ip'][0])
        else:
            icmp_cache[details['ip'][0]] = { "sourceid_count": {details['port'][0]: 1},
                                            "count": 1}
    return False

# return true if packet exhibits behavior of syn flood 
# for a src ip, if this is a SYN packet, check that we've
# received an ACK back (if we send a SYN-ACK) within timeout
# tolerate a consistent 20% success rate
def check_syn(packet, details) -> bool:
    tcplayer = packet[TCP]
    if tcplayer.flags == 'S': # SYN from outside
        if details['ip'][0] in syn_cache: # if already exists, check time constraints
            time = details['time'] # we'll keep on updating the oldest things in the cache
            sport = details['port'][0]
            record = syn_cache[details['ip'][0]]
            if len(list(record['time_port'].keys())) == 0:
                return False
            cached_port = next(iter(record['time_port']))
            oldest = record['time_port'][cached_port]
            # later see if you can do a range of oldest times and take percentage of that
            if time - oldest >= timeout and record['acks']/record['syns'] < 0.2:
                record['count'] += 1
            # still want to store this entry but only if it doesn't exist yet
            if sport not in record['time_port']:
                record['time_port'][sport] = time
            record['syns'] += 1
            # check if we've reached the limit of unacked syns we can tolerate
            if record['count'] >= limit:
                return True

        else: # first SYN from this src ip to dest ip
            #packet.show()
            #print(details['ip'])
            syn_cache[details['ip'][0]] = { "time_port": {details['port'][0]: details['time']},
                                            "syns": 1,
                                            "acks": 0,
                                            "count": 0
                                        }
    elif tcplayer.flags == 'A': # we'll take take the ack only if it we did receive a syn for it previously
        sport = details['port'][0]
        if details['ip'][0] in syn_cache:
            #print(syn_cache[details['ip'][0]])
            record = syn_cache[details['ip'][0]]
            if sport in record['time_port']:
                record['time_port'].pop(sport)
                record['acks'] += 1

    return False

def yaml_output():
    yaml_dump = {}
    keys = list(block_list.keys())
    for key in keys:
        record = block_list[key][0]
        yaml_dump['start timestamp'] = int(float(str(record.timestamps[0])))
        yaml_dump['end timestamp'] = int(float(str(record.timestamps[-1])))
        yaml_dump['source'] = {'mac_address': record.mac[0], 'ipv4_address': record.ip[0], 'ports': str(record.all_unique_ports(0))}
        yaml_dump['target'] = {'mac_address': record.mac[1], 'ipv4_address': record.ip[1], 'ports': str(record.all_unique_ports(1))}
        yaml_dump['attack'] = block_list[key][1]
        print(yaml.dump(yaml_dump)+'---')

# input path to PCAP to get packets as list
pcap = PcapReader(sys.argv[1])

# run analysis over pcap
for packet in pcap:
    p_details = get_basic_deets(packet) # {mac, ip, protocol, port, timestamp}
    if p_details['ip'] == ('',''): # skip because this packet is out of scope
        continue
    if p_details['ip'][0] in block_list: # update our AttackRecord accordingly
        block_list[p_details['ip'][0]][0].happened_again(p_details['time']) # add new timestamp
        block_list[p_details['ip'][0]][0].add_port(p_details['port']) # offending port or id is updated if it is any different
    else:
        placeholder = AttackRecord(p_details['mac'], p_details['ip'], p_details['port'], p_details['time']) # initialize our record object
        if p_details['protocol'] == 'udp':
            if check_udp(packet, p_details):
                placeholder.set_category('UDP Flood')
        elif p_details['protocol'] == 'icmp':
            if check_icmp(packet, p_details):
                placeholder.set_category('ICMP (Ping) Flood')
        elif p_details['protocol'] == 'tcp':
            if check_syn(packet, p_details):
                placeholder.set_category('SYN Flood')

        if placeholder.category != None: # we've parsed the protocol-specific packet and detected something
            block_list[p_details['ip'][0]] = (placeholder, placeholder.category)

yaml_output()
#keys = list(block_list.keys())
