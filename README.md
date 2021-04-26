# SoftVulnSec_FinalProj

## Environment Setup
<Describe docker setup/ running the container>

## Attacks Detected
### ARP Cache Poisoning
ARP Cache Poisoning attacks are detected by first creating a master list of all mappings between IP addresses and MAC addresses. If throughout the analysis of the packet capture the mapping changes, it can be assumed that an ARP Cache Poisoning attack has occurred. This method is not fool proof, and over time mappings certainly can and will change. However, in the scope of this project and that our tool is being used to analyze packet captures, it would be highly unexpected that the mapping would change in the time constraints of a single capture, and we can therefore deduce that the change was malicious.

### TCP Reset Injection
TCP Reset Injection attacks are detected by looking for TCP data packets that follow a TCP reset in the same exchange between client and server. This behavior is indicative of a TCP Reset Injection attack because the reset is forged by a third party and is sent to both sides of the conversation. Therefore, once the forged reset is sent, there are already data packets being transmitted that will still be received but ignored by the recipient because they were told to reset. In a normal case of a reset packet being sent, there would be no data packets that follow.

### Denial of Service (DOS)
