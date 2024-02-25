from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import threading

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPResponse

class Switch:

    def __init__(self):

        self.interfaces = {
            "eth0": "Realtek USB GbE Family Controller #2",
            "eth1": "Realtek USB GbE Family Controller"
        }

        self.switch_table = {

        }

        self.interface_0_stats = InterfaceStats()
        self.interface_1_stats = InterfaceStats()

        self.test_number = 0

    def handle_packet(self, packet, interface_name, target_interface):  # Pridaj 'self' ako prvý argument
        print("======================================================================================")

        print(f"Interface name is {interface_name}")

        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            print(f"Zdrojová MAC adresa: {src_mac}, Cieľová MAC adresa: {dst_mac}")

            if interface_name == "eth0":
                self.interface_0_stats.Ethernet_IN += 1
                self.interface_0_stats.Total_IN += 1
                self.interface_1_stats.Ethernet_OUT += 1
                self.interface_1_stats.Total_OUT += 1
                self.forward_packet(packet, target_interface)
            else:
                self.interface_1_stats.Ethernet_IN += 1
                self.interface_1_stats.Total_IN += 1
                self.interface_0_stats.Ethernet_OUT += 1
                self.interface_0_stats.Total_OUT += 1
                self.forward_packet(packet, target_interface)

            self.add_entry(src_mac, 0, interface_name)

        if IP in packet:

            if interface_name == "eth0":
                self.interface_0_stats.IP_IN += 1
                self.interface_0_stats.Total_IN += 1
                self.interface_1_stats.IP_OUT += 1
                self.interface_1_stats.Total_OUT += 1

            else:
                self.interface_1_stats.IP_IN += 1
                self.interface_1_stats.Total_IN += 1
                self.interface_0_stats.IP_OUT += 1
                self.interface_0_stats.Total_OUT += 1

        if ARP in packet:
                if interface_name == "eth0":
                    self.interface_0_stats.ARP_IN += 1
                    self.interface_0_stats.Total_IN += 1
                    self.interface_1_stats.ARP_OUT += 1
                    self.interface_1_stats.Total_OUT += 1

                else:
                    self.interface_1_stats.ARP_IN += 1
                    self.interface_1_stats.Total_IN += 1
                    self.interface_0_stats.ARP_OUT += 1
                    self.interface_0_stats.Total_OUT += 1

        if TCP in packet:
                if interface_name == "eth0":
                    self.interface_0_stats.TCP_IN += 1
                    self.interface_0_stats.Total_IN += 1
                    self.interface_1_stats.TCP_OUT += 1
                    self.interface_1_stats.Total_OUT += 1

                else:
                    self.interface_1_stats.TCP_IN += 1
                    self.interface_1_stats.Total_IN += 1
                    self.interface_0_stats.TCP_OUT += 1
                    self.interface_0_stats.Total_OUT += 1

        if UDP in packet:
                if interface_name == "eth0":
                    self.interface_0_stats.UDP_IN += 1
                    self.interface_0_stats.Total_IN += 1
                    self.interface_1_stats.UDP_OUT += 1
                    self.interface_1_stats.Total_OUT += 1

                else:
                    self.interface_1_stats.UDP_IN += 1
                    self.interface_1_stats.Total_IN += 1
                    self.interface_0_stats.UDP_OUT += 1
                    self.interface_0_stats.Total_OUT += 1

        if ICMP in packet:
                if interface_name == "eth0":
                    self.interface_0_stats.ICMP_IN += 1
                    self.interface_0_stats.Total_IN += 1
                    self.interface_1_stats.ICMP_OUT += 1
                    self.interface_1_stats.Total_OUT += 1

                else:
                    self.interface_1_stats.ICMP_IN += 1
                    self.interface_1_stats.Total_IN += 1
                    self.interface_0_stats.ICMP_OUT += 1
                    self.interface_0_stats.Total_OUT += 1

        if HTTP in packet:
                if interface_name == "eth0":
                    self.interface_0_stats.HTTP_IN += 1
                    self.interface_0_stats.Total_IN += 1
                    self.interface_1_stats.HTTP_OUT += 1
                    self.interface_1_stats.Total_OUT += 1

                else:
                    self.interface_1_stats.HTTP_IN += 1
                    self.interface_1_stats.Total_IN += 1
                    self.interface_0_stats.HTTP_OUT += 1
                    self.interface_0_stats.Total_OUT += 1

        if HTTPResponse in packet:
                if interface_name == "eth0":
                    self.interface_0_stats.HTTPS_IN += 1
                    self.interface_0_stats.Total_IN += 1
                    self.interface_1_stats.HTTPS_OUT += 1
                    self.interface_1_stats.Total_OUT += 1

                else:
                    self.interface_1_stats.HTTPS_IN += 1
                    self.interface_1_stats.Total_IN += 1
                    self.interface_0_stats.HTTPS_OUT += 1
                    self.interface_0_stats.Total_OUT += 1

        self.show_stats()
        print(self.switch_table)



    def start_listening(self, interface_name, target_interface):

        sniff(iface=self.interfaces[interface_name], prn=lambda packet: self.handle_packet(packet, interface_name, target_interface))



    def  add_entry(self, mac_address, timer, interface):
        self.switch_table[mac_address] = {
            "timer": timer,
            "interface": interface
        }

    def show_stats(self):

        #Show stat for interface 0
        print("ETH 0")
        print(f"Ethernet IN: {self.interface_0_stats.Ethernet_IN}")
        print(f"IP IN: {self.interface_0_stats.IP_IN}")
        print(f"ARP IN: {self.interface_0_stats.ARP_IN}")
        print(f"TCP IN: {self.interface_0_stats.TCP_IN}")
        print(f"UDP IN: {self.interface_0_stats.UDP_IN}")
        print(f"ICMP IN: {self.interface_0_stats.ICMP_IN}")
        print(f"HTTP IN: {self.interface_0_stats.HTTP_IN}")
        print(f"HTTPS IN: {self.interface_0_stats.HTTPS_IN}")
        print(f"Total IN: {self.interface_0_stats.Total_IN}")


        print(f"Ethernet OUT: {self.interface_0_stats.Ethernet_OUT}")
        print(f"IP OUT: {self.interface_0_stats.IP_OUT}")
        print(f"ARP OUT: {self.interface_0_stats.ARP_OUT}")
        print(f"TCP OUT: {self.interface_0_stats.TCP_OUT}")
        print(f"UDP OUT: {self.interface_0_stats.UDP_OUT}")
        print(f"ICMP OUT: {self.interface_0_stats.ICMP_OUT}")
        print(f"HTTP OUT: {self.interface_0_stats.HTTP_OUT}")
        print(f"HTTPS OUT: {self.interface_0_stats.HTTPS_OUT}")
        print(f"Total OUT: {self.interface_0_stats.Total_OUT}")


        #Show stat for interface 1
        print("ETH 1")
        print(f"Ethernet IN: {self.interface_1_stats.Ethernet_IN}")
        print(f"IP IN: {self.interface_1_stats.IP_IN}")
        print(f"ARP IN: {self.interface_1_stats.ARP_IN}")
        print(f"TCP IN: {self.interface_1_stats.TCP_IN}")
        print(f"UDP IN: {self.interface_1_stats.UDP_IN}")
        print(f"ICMP IN: {self.interface_1_stats.ICMP_IN}")
        print(f"HTTP IN: {self.interface_1_stats.HTTP_IN}")
        print(f"HTTPS IN: {self.interface_1_stats.HTTPS_IN}")
        print(f"Total IN: {self.interface_1_stats.Total_IN}")

        print(f"Ethernet OUT: {self.interface_1_stats.Ethernet_OUT}")
        print(f"IP OUT: {self.interface_1_stats.IP_OUT}")
        print(f"ARP OUT: {self.interface_1_stats.ARP_OUT}")
        print(f"TCP OUT: {self.interface_1_stats.TCP_OUT}")
        print(f"UDP OUT: {self.interface_1_stats.UDP_OUT}")
        print(f"ICMP OUT: {self.interface_1_stats.ICMP_OUT}")
        print(f"HTTP OUT: {self.interface_1_stats.HTTP_OUT}")
        print(f"HTTPS OUT: {self.interface_1_stats.HTTPS_OUT}")
        print(f"Total OUT: {self.interface_1_stats.Total_OUT}")

    def forward_packet(self, packet, destination_interface):
        if destination_interface in self.interfaces:
            # Send the packet out of the specified interface
            sendp(packet, iface=self.interfaces[destination_interface], verbose=False)
        else:
            print(f"Cieľové rozhranie {destination_interface} nie je definované.")




class InterfaceStats:
    def __init__(self):
        # Incoming traffic
        self.Ethernet_IN = 0
        self.IP_IN = 0
        self.ARP_IN = 0
        self.TCP_IN = 0
        self.UDP_IN = 0
        self.ICMP_IN = 0
        self.HTTP_IN = 0
        self.HTTPS_IN = 0
        self.Total_IN = 0

        # Outgoing traffic
        self.Ethernet_OUT = 0
        self.IP_OUT = 0
        self.ARP_OUT = 0
        self.TCP_OUT = 0
        self.UDP_OUT = 0
        self.ICMP_OUT = 0
        self.HTTP_OUT = 0
        self.HTTPS_OUT = 0
        self.Total_OUT = 0
