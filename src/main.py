import subprocess, sys, click

@click.command()
@click.option("-pcap", "--pcap-input", type=str, help="Path to input pcap")
@click.option("-d", "--dos", is_flag=True, help="Enable flood checking")
@click.option("-a", "--arp", is_flag=True, help="Enable arp cache poisoning checking")
@click.option("-t", "--tcp-rst", is_flag=True, help="Enable tcp rst injection attack checking")
def run_everything(pcap_input: str, flood: bool, arp: bool, tcp_rst: bool) -> None:

    if dos:
        print('Starting DoS detection\n')
        subprocess.run(["python3", "dos.py", pcap_input])
        print('Finished DoS detection\n')
    if arp:
        print('Starting ARP cache poisoning detection\n')
        subprocess.run(["python3", "arp_cache_poisoning.py", pcap_input])
        print('Finished ARP cache poisoning detection\n')
    if tcp_rst:
        print('Starting TCP RST injection detection\n')
        subprocess.run(["python3", "tcp_rst_injection.py", pcap_input])
        print('Finished TCP RST injection detection\n')

if __name__ == "__main__":
    run_everything()
