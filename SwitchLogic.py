from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import threading

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPResponse
#from Switch_GUI import SwitchGUI

class Switch:

    #def __init__(self, switch_gui: SwitchGUI):
    def __init__(self):

        self.interfaces = {
            "eth0": "Realtek USB GbE Family Controller",
            "eth1": "Realtek USB GbE Family Controller #3"
        }

        #self.switch_gui = switch_gui

        #self.interfaces_stats = {
        #     "interface1": {
        #         "Incoming": {
        #             "Ethernet_IN": 0,
        #             "IP_IN": 0,
        #             "ARP_IN": 0,
        #             "TCP_IN": 0,
        #             "UDP_IN": 0,
        #             "ICMP_IN": 0,
        #             "HTTP_IN": 0,
        #             "HTTPS_IN": 0,
        #             "Total_IN": 0,
        #         },
        #         "Outgoing": {
        #             "Ethernet_OUT": 0,
        #             "IP_OUT": 0,
        #             "ARP_OUT": 0,
        #             "TCP_OUT": 0,
        #             "UDP_OUT": 0,
        #             "ICMP_OUT": 0,
        #             "HTTP_OUT": 0,
        #             "HTTPS_OUT": 0,
        #             "Total_OUT": 0,
        #         }
        #     },
        #     "interface2": {
        #         "Incoming": {
        #             "Ethernet_IN": 0,
        #             "IP_IN": 0,
        #             "ARP_IN": 0,
        #             "TCP_IN": 0,
        #             "UDP_IN": 0,
        #             "ICMP_IN": 0,
        #             "HTTP_IN": 0,
        #             "HTTPS_IN": 0,
        #             "Total_IN": 0,
        #         },
        #         "Outgoing": {
        #             "Ethernet_OUT": 0,
        #             "IP_OUT": 0,
        #             "ARP_OUT": 0,
        #             "TCP_OUT": 0,
        #             "UDP_OUT": 0,
        #             "ICMP_OUT": 0,
        #             "HTTP_OUT": 0,
        #             "HTTPS_OUT": 0,
        #             "Total_OUT": 0,
        #         }
        #     }
        # }


        self.interfaces_stats = {
            "interface1": {
                "Incoming": self.generate_stats_dict(),
                "Outgoing": self.generate_stats_dict()
            },
            "interface2": {
                "Incoming": self.generate_stats_dict(),
                "Outgoing": self.generate_stats_dict()
                }
            }

        # self.switch_table = {
        #
        # }

        #Mac adresses of my interfaces
        self.switch_ports_mac_address = {
            "eth0": "00:0c:29:0d:3e:3c",
            "eth1": "00:0c:29:0d:3e:46"
        }

        # Mac address table
        self.mac_address_table = MacAddressTable()

        self.stop_threads = False

        self.packet_number = 0
    def handle_packet(self, packet, interface_name, target_interface):

        is_looping = False

        # Zisti správny kľúč pre aktuálne rozhranie
        current_interface_key = "interface1" if interface_name == "eth0" else "interface2"

        if Ether in packet:
            src_mac = packet['Ether'].src
            dst_mac = packet['Ether'].dst

            # Print source port
            print("Zdrojovy port je: " + interface_name)
            print(f"Zdrojová MAC adresa: {src_mac}, Cieľová MAC adresa: {dst_mac}")

            if self.mac_address_table.get_interface(src_mac) is None:
                self.mac_address_table.add_entry(src_mac, 0, interface_name)

            # Check if the src mac address is in mac table of switch ports
            if src_mac in self.switch_ports_mac_address.values():
                is_looping = True

            #print(f"Interface name is:  + {interface_name} and interface associated with src_mac is: {self.mac_address_table.get_interface(src_mac)}")

            elif self.mac_address_table.get_interface(src_mac) != interface_name:
                is_looping = True


        if not is_looping:

            protocol_map = {
                Ether: "Ethernet",
                IP: "IP",
                ARP: "ARP",
                TCP: "TCP",
                UDP: "UDP",
                ICMP: "ICMP"
            }

            # Iterate over the protocol_map
            for protocol, key in protocol_map.items():
                # If the packet is of the current protocol type, increment the corresponding count
                if protocol in packet:
                    self.interfaces_stats[current_interface_key]["Incoming"][key] += 1

            # Check for HTTP and HTTPS separately as they are identified by destination port
            if TCP in packet:
                if packet[TCP].dport == 80:
                    self.interfaces_stats[current_interface_key]["Incoming"]["HTTP"] += 1
                elif packet[TCP].dport == 443:
                    self.interfaces_stats[current_interface_key]["Incoming"]["HTTPS"] += 1

            # Increment the total incoming traffic count
            self.interfaces_stats[current_interface_key]["Incoming"]["Total"] += 1

            #self.switch_gui.update_traffic(current_interface_key, "Incoming", stats_values)

            self.forward_packet(packet, target_interface)

            # Print total incoming traffic for both interfaces

            self.packet_number += 1

            print(f"Packet number: {self.packet_number}")
            self.mac_address_table.show_table()

        #print(f"Total incoming traffic: {self.interfaces_stats['interface1']['Incoming']['Total_IN'] + self.interfaces_stats['interface2']['Incoming']['Total_IN']}")


    #def start_listening(self, interface_name, target_interface):

     #   sniff(iface=self.interfaces[interface_name], prn=lambda packet: self.handle_packet(packet, interface_name, target_interface))

    # def start_listening(self, interface_name, target_interface):
    #     #Úprava: Kontrola `stop_threads` pred a počas príjmu paketov
    #     def custom_packet_handler(packet):
    #         if self.stop_threads:  # Ak je vlajka nastavená, prestane počúvať
    #             return False  # Vráti False pre zastavenie sniffing
    #         self.handle_packet(packet, interface_name, target_interface)
    #
    #     sniff(iface=self.interfaces[interface_name],stop_filter=lambda x: self.stop_threads)

    def start_listening(self, interface_name, target_interface):
        # Úprava: Kontrola `stop_threads` pred a počas príjmu paketov
        def custom_packet_handler(packet):
            if self.stop_threads:  # Ak je vlajka nastavená, prestane počúvať
                return False  # Vráti False pre zastavenie sniffing
            self.handle_packet(packet, interface_name, target_interface)

        sniff(iface=self.interfaces[interface_name], prn=custom_packet_handler, stop_filter=lambda x: self.stop_threads)

    def show_interface_stats(self):
        # Header for the stats display
        print("Interface Traffic Statistics:\n")

        # Iterating through each interface in the dictionary
        for interface, traffic_types in self.interfaces_stats.items():
            print(f"--- {interface.upper()} ---")  # Display the interface name

            # Iterating through incoming and outgoing traffic stats
            for direction, stats in traffic_types.items():
                print(f"\n  {direction.capitalize()} Traffic:")
                # Iterating through each traffic type and printing its count
                for traffic_type, count in stats.items():
                    # Printing each traffic type's count in a readable format
                    print(f"    {traffic_type}: {count}")
                print("")  # Adding a newline for better readability between sections

            # Separating interfaces for clarity
            print("======================================\n")


    def forward_packet(self, packet, destination_interface):

        if destination_interface in self.interfaces:
            # Send the packet out of the specified interface

            # Zisti správny kľúč pre aktuálne rozhranie
            current_interface_key = "interface1" if destination_interface == "eth0" else "interface2"

            # Define a dictionary to map protocol types to their keys in interfaces_stats
            protocol_map = {
                Ether: "Ethernet",
                IP: "IP",
                ARP: "ARP",
                TCP: "TCP",
                UDP: "UDP",
                ICMP: "ICMP"
            }

            # Iterate over the protocol_map
            for protocol, key in protocol_map.items():
                # If the packet is of the current protocol type, increment the corresponding count
                if protocol in packet:
                    self.interfaces_stats[current_interface_key]["Outgoing"][key] += 1

            # Check for HTTP and HTTPS separately as they are identified by destination port
            if TCP in packet:
                if packet[TCP].dport == 80:
                    self.interfaces_stats[current_interface_key]["Outgoing"]["HTTP"] += 1
                elif packet[TCP].dport == 443:
                    self.interfaces_stats[current_interface_key]["Outgoing"]["HTTPS"] += 1

            # Increment the total outgoing traffic count
            self.interfaces_stats[current_interface_key]["Outgoing"]["Total"] += 1

            sendp(packet, iface=self.interfaces[destination_interface], verbose=False)
        else:
            print(f"Cieľové rozhranie {destination_interface} nie je definované.")

    def get_traffic_stats(self, interface_name, direction):
        # Check if the interface and direction are valid
        if interface_name in self.interfaces_stats and direction in self.interfaces_stats[interface_name]:
            # Get the stats for the specified interface and direction
            stats_dict = self.interfaces_stats[interface_name][direction]

            # Convert the stats dictionary to a list and return it
            return list(stats_dict.values())
        else:
            print("Invalid interface name or direction.")
            return []

    def generate_stats_dict(self):
        return {
            "Ethernet": 0,
            "IP": 0,
            "ARP": 0,
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "HTTP": 0,
            "HTTPS": 0,
            "Total": 0,
        }

# Class for mac address table

class MacAddressTable:

        def __init__(self):
            self.table = {}

        def add_entry(self, mac_address, timer, interface):
            self.table[mac_address] = {
                "timer": timer,
                "interface": interface
            }

        def show_table(self):
            print("MAC Address Table:\n")
            for mac_address, entry in self.table.items():
                print(f"MAC Address: {mac_address}, Timer: {entry['timer']}, Interface: {entry['interface']}")
            print("======================================\n")

        def remove_entry(self, mac_address):
            if mac_address in self.table:
                del self.table[mac_address]
                print(f"Záznam pre MAC adresu {mac_address} bol odstránený.")
            else:
                print(f"Záznam pre MAC adresu {mac_address} neexistuje.")


        # Return interface for mac address
        def get_interface(self, mac_address):
            if mac_address in self.table:
                return self.table[mac_address]["interface"]
            else:
                return None




if __name__ == "__main__":
    print("Switch logic")




