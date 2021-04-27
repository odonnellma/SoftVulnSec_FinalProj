# SoftVulnSec_FinalProj

## Environment Setup
To build the docker container:

Navigate to the same directory as the Dockerfile, ```image_name``` will be the name of the image.
```bash
docker build -t image_name .
```
To run the resulting image:  
```bash
docker run -v ${local_pcap_file}:/tmp/pcap_to_test.pcap image_name /tmp/pcap_to_test.pcap [OPTIONS]
```

Our OPTIONS include the flag -a for arp cache poisoning detection, -t for tcp reset injection detection, -d for denial of service (flood attacks) detection, or all 3 to run all detection modules on the input pcap.
The docker argument ```-v``` followed by /local/absolute/path:/path/in/container mounts your local volume to a location inside the container so that the container can access that file. In this case the pcap is shared with the container to be scanned. 

## ICMP Flood Detection Example
These examples are based off of our test pcaps, which we've loaded into the docker container. They are all in the directory /tmp/pcaps/
Build: 
```bash
docker build -t test .
```
Run: 
```bash
docker run test /tmp/pcaps/icmp_flood.pcap -d
```

## ARP Cache Poisoning Example with All Modules
Build: 
```bash
docker build -t test .
```
Run: 
```bash
docker run test /tmp/pcaps/arp_pcap.pcap -dat
```

## Attacks Detected
### ARP Cache Poisoning
ARP Cache Poisoning attacks are detected by first creating a master list of all mappings between IP addresses and MAC addresses. If throughout the analysis of the packet capture the mapping changes, it can be assumed that an ARP Cache Poisoning attack has occurred. This method is not fool proof, and over time mappings certainly can and will change. However, in the scope of this project and that our tool is being used to analyze packet captures, it would be highly unexpected that the mapping would change in the time constraints of a single capture, and we can therefore deduce that the change was malicious.

### TCP Reset Injection
TCP Reset Injection attacks are detected by looking for TCP data packets that follow a TCP reset in the same exchange between client and server. This behavior is indicative of a TCP Reset Injection attack because the reset is forged by a third party and is sent to both sides of the conversation. Therefore, once the forged reset is sent, there are already data packets being transmitted that will still be received but ignored by the recipient because they were told to reset. In a normal case of a reset packet being sent, there would be no data packets that follow.

### Denial of Service (DoS)
DoS attacks are detected by generally observing and tracking different flood behaviors across several packets. For SYN flood behavior, for the oldest client SYN packets we track (within some timeframe) client ACK packets for the corresponding server SYN-ACK packets, and ensure the proportion of unacknowledged SYN-ACKs to SYNs doesn't breach a togglable threshold for any number of source IPs. For ICMP (Ping) flood behavior, we check if the server has received more than some allowed number of echo-requests (togglable), either from the same source port or a range of source ports, for any number of source IPs. For UDP flood behavior, we track UDP traffic heading to unknown ports on the server within some timeframe, ensuring illegitimate (or unknown) UDP traffic was sent not within some togglable rate-limited time threshold.
