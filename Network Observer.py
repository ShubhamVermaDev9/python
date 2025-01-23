from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import os

# Function to handle captured packets
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src  # Source IP address
        dst_ip = packet[IP].dst  # Destination IP address

        # Identify the protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Other"

        # Get the timestamp for logging
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Format the log message
        log = f"{timestamp} | {protocol} | {src_ip} -> {dst_ip}"
        
        # Display the log in the console
        print(log)

        # Save the log to a file
        with open("network_traffic_log.txt", "a") as log_file:
            log_file.write(log + "\n")

# Start sniffing packets
def start_sniffing():
    print("Starting network traffic monitor...")
    print("Press Ctrl+C to stop.")
    print("Logs are saved to 'network_traffic_log.txt'.\n")
    print("Timestamp            | Protocol | Source IP          -> Destination IP")
    print("-" * 70)

    # Sniff packets with IP layer and send each packet to the callback function
    sniff(filter="ip", prn=packet_callback, store=0)

# Main function
if __name__ == "__main__":
    # Clear the log file if it exists
    if os.path.exists("network_traffic_log.txt"):
        open("network_traffic_log.txt", "a").close()

    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\nNetwork Traffic Monitor stopped.")
        print("Logs saved to 'network_traffic_log.txt'.")