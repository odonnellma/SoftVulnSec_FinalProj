import subprocess, sys, click

@click.command()
@click.option("-pcap", "--pcap-input", type=str, help="Path to input pcap")
#@click.option("-a", "--all-attacks", is_flag=True, help="Enable checking pcap for all attacks")
@click.option("-f", "--flood", is_flag=True, help="Enable flood checking")
@click.option("-arp", "--arp", is_flag=True, help="Enable arp cache poisoning checking")
@click.option("-tcp", "--tcp-rst", is_flag=True, help="Enable tcp rst injection attack checking")
def run_everything(pcap_input: str, flood: bool, arp: bool, tcp_rst: bool) -> None:

    if flood:
        subprocess.run(["python3", "dos.py", pcap_input])
    if arp:
        subprocess.run(["python3", "arp_cache_poisoning.py", pcap_input])
    if tcp_rst:
        subprocess.run(["python3", "tcp_rst_injection.py", pcap_input])

if __name__ == "__main__":
    run_everything()
