import hashlib
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from MacAddressTable import MacAddressTable

class Switch:

    #def __init__(self, switch_gui: SwitchGUI):
    def __init__(self):

        self.interfaces = {
            "eth0": "Realtek USB GbE Family Controller",
            "eth1": "Realtek USB GbE Family Controller #3"
        }

        self.last_handled_packet_hashes = deque(maxlen=20)

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

        #print("---------------------------------------------------------------------------------------")
        #print("Handle packet method")

        is_looping = False

        packet_hash = self.get_packet_hash(packet)
        #print(f"Packet hash: {packet_hash}")

        # Zisti správny kľúč pre aktuálne rozhranie
        current_interface_key = "interface1" if interface_name == "eth0" else "interface2"

        # Check if the packet is in the deque
        if self.is_packet_in_deque(packet_hash):
            #print("Packet has been handled already. Dropping the packet.")
            is_looping = True

        else:
            # Add the packet to the deque
            self.add_packet(packet_hash)

        vales = self.get_traffic_stats(current_interface_key, "Incoming")
        #print(f"Interface {current_interface_key} incoming traffic: {vales}")


        # New logic of handling duplicate traffic in network


        if not is_looping:

            if Ether in packet:
                src_mac = packet['Ether'].src
                dst_mac = packet['Ether'].dst

            # Print source port
            # print("Zdrojovy port je: " + interface_name)
            # print(f"Zdrojová MAC adresa: {src_mac}, Cieľová MAC adresa: {dst_mac}")

            # if self.mac_address_table.get_interface(src_mac) is None:
                if src_mac != "14-4F-D7-C5-30-51" or src_mac != "00-E0-4C-68-03-C4":
                    self.mac_address_table.add_entry(src_mac, 15, interface_name)

                #self.decrement_mac_table_timer()
            # Check if the src mac address is in mac table of switch ports
            # if src_mac in self.switch_ports_mac_address.values():
            # is_looping = True

            # print(f"Interface name is:  + {interface_name} and interface associated with src_mac is: {self.mac_address_table.get_interface(src_mac)}")

            # elif self.mac_address_table.get_interface(src_mac) != interface_name:
            # is_looping = True

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


            # if ICMP in packet:
            #     print("---------------------------------------------------------------------------------------")
            #     print("Handle packet method, THIS IS AN ICMP PACKET")
            #     print("Zdrojovy port je: " + interface_name)
            #     print(f"Zdrojová MAC adresa: {src_mac}, Cieľová MAC adresa: {dst_mac}")
            #     print("Sequence number:", packet[ICMP].seq)


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



            #print(f"Packet number: {self.packet_number}")
            #self.mac_address_table.show_table()

        #print(f"Total incoming traffic: {self.interfaces_stats['interface1']['Incoming']['Total_IN'] + self.interfaces_stats['interface2']['Incoming']['Total_IN']}")


    #def start_listening(self, interface_name, target_interface):

     #   sniff(iface=self.interfaces[interface_name], prn=lambda packet: self.handle_packet(packet, interface_name, target_interface))

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
                    #Printing each traffic type's count in a readable format
                    print(f"    {traffic_type}: {count}")
                    print("")  # Adding a newline for better readability between sections

            # Separating interfaces for clarity
            print("======================================\n")


    def forward_packet(self, packet, destination_interface):


        #print("This is a forwar packet method")

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

            #if ICMP in packet:
                #print("This is an ICMP packet that will be forwarded")
                #print("Sequence number of ICMP packet:", packet[ICMP].seq)

            # Check for HTTP and HTTPS separately as they are identified by destination port
            if TCP in packet:
                if packet[TCP].dport == 80:
                    self.interfaces_stats[current_interface_key]["Outgoing"]["HTTP"] += 1
                elif packet[TCP].dport == 443:
                    self.interfaces_stats[current_interface_key]["Outgoing"]["HTTPS"] += 1

            # Increment the total outgoing traffic count
            self.interfaces_stats[current_interface_key]["Outgoing"]["Total"] += 1

            if destination_interface in self.interfaces:
                try:
                    # Attempt to send the packet out of the specified interface
                    sendp(packet, iface=self.interfaces[destination_interface], verbose=False)
                except OSError as e:
                    # Handle the error gracefully
                    print(f"Error sending packet through interface {destination_interface}: {e}")
            else:
                print(f"Cieľové rozhranie {destination_interface} nie je definované.")

    def get_traffic_stats(self, interface_name, direction):
        # Check if the interface and direction are valid
        if interface_name in self.interfaces_stats and direction in self.interfaces_stats[interface_name]:
            # Get the stats for the specified interface and direction
            stats_dict = self.interfaces_stats[interface_name][direction]

            # Convert the stats dictionary to a list and return it
            # Print the number of elements in the list
            #print(f"Number of elements in the list: {len(list(stats_dict.values()))}")
            return list(stats_dict.values())
        else:
           # print("Invalid interface name or direction.")
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

    import hashlib

    def get_packet_hash(self, packet):
        packet_bytes = raw(packet)
        sha256_hash = hashlib.sha256(packet_bytes).hexdigest()
        return sha256_hash

    # Function to add a packet to the deque
    def add_packet(self, packet_hash):
        #self.last_handled_packets_hashes.append(packet)
        self.last_handled_packet_hashes.append(packet_hash)


    def is_packet_in_deque(self, packet_hash):
        # Iterate over the deque
        for p in self.last_handled_packet_hashes:
            # If the hash of the current packet matches the given hash, return True
            if p == packet_hash:
                return True
        # If no match was found after iterating over the entire deque, return False
        return False

    def set_interface_name(self, interface1, interface2):
        self.interfaces["eth0"] = interface1
        self.interfaces["eth1"] = interface2

    def return_mac_table(self):
        return self.mac_address_table.get_table()

    # Method that decrement timer for each mac address in mac table
    # def decrement_mac_table_timer(self):
    #     for mac_address, entry in self.mac_address_table.get_table().items():
    #         entry["timer"] -= 1
    #         if entry["timer"] == 0:
    #             self.mac_address_table.remove_entry(mac_address)


    # Method that decrement timer for each mac address in mac table
    # def decrement_mac_table_timer(self):
    #
    #     while True:
    #         print("---------------------------------------------")
    #         print("Decrementing mac table timer")
    #         for mac_address, entry in self.mac_address_table.get_table().items():
    #             entry["timer"] = int(entry["timer"]) - 1
    #
    #             if entry["timer"] == 0:
    #                 self.mac_address_table.remove_entry(mac_address)
    #
    #         time.sleep(1)

    def decrement_mac_table_timer(self):
        while True:
            # Create a copy of the keys
            mac_addresses = list(self.mac_address_table.get_table().keys())
            for mac_address in mac_addresses:
                entry = self.mac_address_table.get_table().get(mac_address)
                # Check if the entry still exists
                if entry is not None:
                    entry["timer"] = int(entry["timer"]) - 1
                    if entry["timer"] == 0:
                        self.mac_address_table.remove_entry(mac_address)
            time.sleep(1)

    def clear_mac_table(self):
        self.mac_address_table.clear_table()


if __name__ == "__main__":
    print("Switch logic")




