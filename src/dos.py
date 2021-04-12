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
block_list = []

# input path to PCAP to get packets as list
pcap = PcapReader(sys.argv[1])

