import os
from scapy.all import sniff

def print_boxed_title(title):
    # Get terminal width
    rows, columns = os.popen('stty size', 'r').read().split()
    terminal_width = int(columns)
    
    # Prepare title with padding
    padded_title = " {} ".format(title)
    if len(padded_title) < terminal_width:
        # Center title with padding
        pad_len = (terminal_width - len(padded_title)) // 2
        padded_title = " " * pad_len + padded_title + " " * pad_len
    
    print("+" + "-" * (terminal_width - 2) + "+")
    print("|" + padded_title.center(terminal_width - 2) + "|")
    print("+" + "-" * (terminal_width - 2) + "+")

def main():
    # Clear the console
    print("\033[H\033[J", end="")
    
    # Display a welcome message and instructions within a box
    print_boxed_title("Welcome to PySniff Pro")
    print("A Customizable Network Packet Sniffer\n")
    print("Please follow the prompts to customize your sniffing session.\n")

    # Prompt for user input
    protocol_filter = input("Enter a protocol to filter by (tcp, udp, icmp, etc.), or 'none' for no filter: ").strip().lower()
    interface = input("Enter the interface to sniff on, or 'default' for the default interface: ").strip()
    packet_count = input("Enter the number of packets to capture ('0' for indefinite): ").strip()

    # Validate and prepare the filter
    bpf_filter = '' if protocol_filter == 'none' else protocol_filter

    # Validate and prepare the interface
    interface = None if interface == 'default' else interface

    # Validate and prepare the packet count
    try:
        packet_count = int(packet_count)
    except ValueError:
        print("Invalid packet count. Defaulting to indefinite.")
        packet_count = 0

    # Start sniffing with the user's preferences
    print("\nStarting packet capture...")
    sniff(iface=interface, prn=process_packet, count=packet_count, filter=bpf_filter, store=False)
    print("Packet capture complete.")

# Function to process each packet
def process_packet(packet):
    print(packet.summary())

if __name__ == '__main__':
    main()

