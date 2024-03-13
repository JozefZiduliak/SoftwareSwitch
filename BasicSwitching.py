from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
# Global variable to store the destination interface
destination_interface = None

def packet_callback(packet):
    global destination_interface

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")

        # Construct a new Ethernet frame with the destination MAC address
        # you want to send the packet to and send it out through the specified interface
        new_packet = Ether(src=src_mac, dst=dst_mac) / IP(packet[IP])
        sendp(new_packet, iface=destination_interface)
        print("Packet sent to destination interface.")

def capture_packets(interface, dest_interface, count=10):
    global destination_interface
    destination_interface = dest_interface

    print(f"Capturing {count} packets on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=count)

if __name__ == "__main__":
    interface = input("Enter the interface to capture packets from (e.g., 'eth0'): ")
    dest_interface = input("Enter the interface to send analyzed packets to (e.g., 'eth1'): ")
    num_packets = int(input("Enter the number of packets to capture: "))
    capture_packets(interface, dest_interface, num_packets)