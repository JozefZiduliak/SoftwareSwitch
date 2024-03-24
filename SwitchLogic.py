import hashlib
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from MacAddressTable import MacAddressTable
import time

class Switch:

    #def __init__(self, switch_gui: SwitchGUI):
    def __init__(self):

        self.mac_addresses_to_ignore = ["14:4f:d7:c5:30:51", "00:e0:4c:40:70:b1", "f8:e9:4f:5b:91:84", "f8:e9:4f:76:f8:16"]

        self.timer_value = 15

        self.interfaces = {

        }

        self.stats_lock = threading.Lock()
        self.mac_address_table_lock = threading.Lock()

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

        # Stores time of the last packet on each interface
        # self.last_packet_time = {
        #     "interface1": 0,
        #     "interface2": 0
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
    def handle_packet(self, packet, interface_name):

        # print("---------------------------------------------------------------------------------------")
        # print("Handle packet method")

        #print("Value of self.timer is ", self.timer_value)


        is_looping = False

        packet_hash = self.get_packet_hash(packet)

        # print(f"Current interface name: {interface_name}")

        # Zisti správny kľúč pre aktuálne rozhranie
        current_interface_key = "interface1" if interface_name == "Ethernet 0" else "interface2"

        # print(f"Current interface key: {current_interface_key}")


        # Check if the deque contains old entries and clear them
        self.check_and_clear_deque()

        # Check if the packet is in the deque
        if self.is_packet_in_deque(packet_hash):

            is_looping = True

        else:
            # Add the packet to the deque
            self.add_packet(packet_hash)


        # New logic of handling duplicate traffic in network
        if not is_looping:


            if Ether in packet:
                src_mac = packet['Ether'].src
                dst_mac = packet['Ether'].dst

                # Update time of the last packet on the interface
                #self.last_packet_time[interface_name] = time.time()

                if src_mac in self.mac_addresses_to_ignore:
                    return None

                # Add later logic for ignoring packets from switch itself
                with self.mac_address_table_lock:
                    self.mac_address_table.add_entry(src_mac, self.timer_value, interface_name)

            else:
                return None

            print(f"Updated timer for interface {interface_name}")


            protocol_map = {
                Ether: "Ethernet",
                IP: "IP",
                ARP: "ARP",
                TCP: "TCP",
                UDP: "UDP",
                ICMP: "ICMP"
            }

            with self.stats_lock:

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


            # Is it broadcast?
            if packet[Ether].dst == "ff:ff:ff:ff:ff:ff":

                #Send it out of the other interface
                # Loop through the interfaces
                for interface in self.interfaces:
                    # If the current interface is not the one the packet came from, forward the packet
                    if interface != interface_name:
                        self.forward_packet(packet, interface)


            else:
                with self.mac_address_table_lock:
                # Check if the destination MAC address is in the MAC address table

                    if packet[Ether].dst in self.mac_address_table.get_table():

                        # Get the interface associated with the destination MAC address
                        destination_interface = self.mac_address_table.get_interface(packet[Ether].dst)

                        if destination_interface != interface_name:
                            # Forward the packet out of the interface associated with the destination MAC address
                            self.forward_packet(packet, destination_interface)

                    else:
                        # If the destination MAC address is not in the MAC address table, broadcast the packet
                        # Loop through the interfaces
                        for interface in self.interfaces:
                            # If the current interface is not the one the packet came from, forward the packet
                            if interface != interface_name:
                                self.forward_packet(packet, interface)

            self.packet_number += 1



    def start_listening(self, interface_name):
        # Úprava: Kontrola `stop_threads` pred a počas príjmu paketov
        def custom_packet_handler(packet):
            if self.stop_threads:  # Ak je vlajka nastavená, prestane počúvať
                return False  # Vráti False pre zastavenie sniffing
            self.handle_packet(packet, interface_name)

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
            current_interface_key = "interface1" if destination_interface == "Ethernet 0" else "interface2"

            # Define a dictionary to map protocol types to their keys in interfaces_stats
            protocol_map = {
                Ether: "Ethernet",
                IP: "IP",
                ARP: "ARP",
                TCP: "TCP",
                UDP: "UDP",
                ICMP: "ICMP"
            }

            with self.stats_lock:
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

    #Function to add a packet to the deque
    # def add_packet(self, packet_hash):
    #     #self.last_handled_packets_hashes.append(packet)
    #     self.last_handled_packet_hashes.append(packet_hash)

    def add_packet(self, packet_hash):
        # Add the packet hash and the current time to the deque
        self.last_handled_packet_hashes.append((packet_hash, time.time()))

    # def is_packet_in_deque(self, packet_hash):
    #     # Iterate over the deque
    #     for p in self.last_handled_packet_hashes:
    #         # If the hash of the current packet matches the given hash, return True
    #         if p == packet_hash:
    #             return True
    #     # If no match was found after iterating over the entire deque, return False
    #     return False

    def is_packet_in_deque(self, packet_hash):
        # Iterate over the deque
        for p, _ in self.last_handled_packet_hashes:
            # If the hash of the current packet matches the given hash, return True
            if p == packet_hash:
                return True
        # If no match was found after iterating over the entire deque, return False
        return False

    # def check_and_clear_deque(self):
    #     # If the deque is not empty
    #     if self.last_handled_packet_hashes:
    #         # Get the time the newest packet was added
    #         _, newest_time = self.last_handled_packet_hashes[-1]
    #         # If more than 5 seconds have passed since the newest packet was added
    #         if time.time() - newest_time > 5:
    #             # Clear the deque
    #             self.last_handled_packet_hashes.clear()

    def check_and_clear_deque(self):
        # If the deque is not empty
        if self.last_handled_packet_hashes:
            # Get the time the first packet was added
            _, oldest_time = self.last_handled_packet_hashes[0]
            # If more than 5 seconds have passed since the first packet was added
            if time.time() - oldest_time > 10:
                # Clear the deque
                self.last_handled_packet_hashes.clear()

    def set_interface_name(self, interface1, interface2):
        self.interfaces["Ethernet 0"] = interface1
        self.interfaces["Ethernet 1"] = interface2

    # def return_mac_table(self):
    #     with self.mac_address_table_lock:
    #         self.mac_address_table.remove_expired_entries(self.timer_value)
    #
    #         # Check if the last packet was received more than 10 seconds ago
    #         for interface in self.interfaces:
    #             print(interface)
    #             if time.time() - self.last_packet_time[interface] > 10:
    #                 self.mac_address_table.delete_entries_for_interface(interface)
    #
    #         return self.mac_address_table.get_table()

    def return_mac_table(self):
        with self.mac_address_table_lock:
            self.mac_address_table.remove_expired_entries(self.timer_value)

            # Check if the last packet was received more than 10 seconds ago
            # for interface in self.interfaces:
            #     # Ensure the interface is in the last_packet_time dictionary
            #     if interface not in self.last_packet_time:
            #         self.last_packet_time[interface] = 0
            #
            #     if time.time() - self.last_packet_time[interface] > 10:
            #         self.mac_address_table.delete_entries_for_interface(interface)

            return self.mac_address_table.get_table()


    # Original decrement mac table timer function
    # def decrement_mac_table_timer(self):
    #     while True:
    #         # Create a copy of the keys
    #         mac_addresses = list(self.mac_address_table.get_table().keys())
    #         for mac_address in mac_addresses:
    #             entry = self.mac_address_table.get_table().get(mac_address)
    #             # Check if the entry still exists
    #             if entry is not None:
    #                 entry["timer"] = int(entry["timer"]) - 1
    #                 if entry["timer"] == 0:
    #                     self.mac_address_table.remove_entry(mac_address)
    #         time.sleep(1)

    # Function that locks the mac address table and decrements the timer for each entry
    def decrement_mac_table_timer(self):
        while True:
            # Create a copy of the keys
            mac_addresses = list(self.mac_address_table.get_table().keys())
            for mac_address in mac_addresses:
                with self.mac_address_table_lock:
                    entry = self.mac_address_table.get_table().get(mac_address)
                    # Check if the entry still exists
                    if entry is not None:
                        entry["timer"] = int(entry["timer"]) - 1
                        if entry["timer"] == 0:
                            self.mac_address_table.remove_entry(mac_address)
            time.sleep(1)


    def clear_mac_table(self):
        with self.mac_address_table_lock:
            self.mac_address_table.clear_table()

    def set_timer_value(self, timer_value):
        self.timer_value = timer_value

    def clear_stats(self, interface_name):
        if interface_name in self.interfaces_stats:
            self.interfaces_stats[interface_name]["Incoming"] = self.generate_stats_dict()
            self.interfaces_stats[interface_name]["Outgoing"] = self.generate_stats_dict()
        else:
            print("Invalid interface name.")


if __name__ == "__main__":
    print("Switch logic")




