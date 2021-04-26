import subprocess, sys, click

@click.command()
@click.option("-pcap", "--pcap-input", type=str, help="Path to input pcap")
@click.option("-a", "--all-attacks", is_flag=True, help="Enable checking pcap for all attacks")
@click.option("-f", "--flood", is_flag=True, help="Enable flood checking")
def run_everything(pcap_input: str, flood: bool, all_attacks: bool) -> None:
    if flood:
        subprocess.run(["python3", "dos.py", pcap_input])

if __name__ == "__main__":
    run_everything()
