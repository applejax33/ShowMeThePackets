import sys
import random
import time
import argparse
from scapy.all import *

# Define version
version = 0.3

def determineMACAddress():
    """
    Determine the MAC address of the current system.
    Assumes the last interface's MAC address is the desired one.
    """
    try:
        localMACs = [get_if_hwaddr(i) for i in get_if_list() if get_if_hwaddr(i) != "00:00:00:00:00:00"]
        return localMACs[-1] if localMACs else "00:00:00:00:00:00"
    except Exception as e:
        print(f"Error determining MAC address: {e}")
        sys.exit(1)

def spoofIsAt(pkt):
    try:
        isAt = ARP(op=2, hwsrc=sourceMAC, psrc=pkt[ARP].pdst,
                   hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
        print(f"[INFO] Sending ARP reply to takeover {isAt.psrc}")
        send(isAt, verbose=0)
    except Exception as e:
        print(f"[ERROR] Failed to send ARP reply: {e}")

def spoofSYNACK(pkt):
    try:
        if (pkt[IP].src in answered and answered[pkt[IP].src] == pkt[IP].dport):
            return
        response = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                   TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport,
                       seq=random.randint(1, 2400000000),
                       ack=pkt[TCP].seq + 1,
                       window=random.randint(1, 100),
                       flags='SA')  # SYN-ACK
        send(response, verbose=0)
        answered[response[IP].dst] = response[TCP].sport
        print(f"[INFO] Sent spoofed SYN-ACK to {pkt[IP].src}:{pkt[TCP].sport}")
    except Exception as e:
        print(f"[ERROR] Failed to send SYN-ACK: {e}")

def spoofACK(pkt):
    try:
        response = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                   TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport,
                       seq=pkt[TCP].ack,
                       ack=pkt[TCP].seq + (len(pkt[Raw].load) if Raw in pkt else 0),
                       window=0,
                       flags='A')  # ACK
        send(response, verbose=0)
        print(f"[INFO] Sent spoofed ACK with zero window to {pkt[IP].src}:{pkt[TCP].sport}")
    except Exception as e:
        print(f"[ERROR] Failed to send ACK: {e}")

def packet_received(pkt):
    try:
        if pkt[Ether].src != sourceMAC:
            # Handle ARP requests
            if ARP in pkt and pkt[ARP].op == 1:  # ARP who-has
                if pkt[ARP].pdst in whohases and pkt[Ether].src != sourceMAC:
                    now = time.time()
                    delta = now - whohases[pkt[ARP].pdst]
                    if delta <= 1.25:
                        spoofIsAt(pkt)
                whohases[pkt[ARP].pdst] = time.time()

            # Handle TCP SYN packets
            elif TCP in pkt and pkt[TCP].flags == 'S':
                spoofSYNACK(pkt)

            # Handle TCP ACK packets
            elif TCP in pkt and pkt[TCP].flags == 'A':
                spoofACK(pkt)
    except Exception as e:
        print(f"[ERROR] Packet handling failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced LaBrea Tarpit using Scapy.")
    parser.add_argument("--interface", "-i", help="Network interface to listen on.", required=False)
    parser.add_argument("--safe-mode", "-s", action="store_true", help="Enable safe mode (no ARP spoofing).")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output.")
    args = parser.parse_args()

    global sourceMAC, answered, whohases, safe_mode, verbose

    answered = dict()
    whohases = dict()
    safe_mode = args.safe_mode
    verbose = args.verbose
    sourceMAC = determineMACAddress()

    print(f"[INFO] Scapified LaBrea v{version}")
    print(f"[INFO] Source MAC: {sourceMAC}")
    print(f"[INFO] Safe mode: {'Enabled' if safe_mode else 'Disabled'}")

    try:
        sniff(iface=args.interface, prn=packet_received, store=0)
    except PermissionError:
        print("[ERROR] Permission denied. Run the script with elevated privileges (sudo).")
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")

if __name__ == "__main__":
    main()