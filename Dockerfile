FROM ubuntu:20.10

WORKDIR /tmp

# adding detection modules
ADD /src/main.py .
ADD /src/dos.py .
ADD /src/arp_cache_poisoning.py .
ADD /src/tcp_rst_injection.py .

# adding test pcaps
ADD /src/pcaps/arp_pcap.pcap .
ADD /src/pcaps/arp-poisoning.pcap .
ADD /src/pcaps/icmp_flood.pcap .
ADD /src/pcaps/syn_flood.pcap .
ADD /src/pcaps/udp_flood.pcap .

RUN apt update -y

# We ended up not needing the below installs
# Installing text editors
#RUN apt install vim -y
#RUN apt install emacs -y
#RUN apt install nano -y
#RUN apt install less -y

#Installing networking tools
#RUN apt install curl -y
#RUN apt install net-tools -y
#RUN apt install netcat -y

#Installing Python3
RUN apt install python3 -y

RUN apt install pip -y

# Installing pip
RUN pip install --upgrade pip && \
    pip install scapy && \
    pip install oyaml && \
    pip install click

ENTRYPOINT ["python3", "main.py", "-pcap"]
