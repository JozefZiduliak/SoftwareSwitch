import threading
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP

# TODO  Add locks to the methods that modify the rules list
# TODO  Explicit dany was changed to explicit allow


class AccesControlList:

    def __init__(self):
        self.rules = []
        self.acl_lock = threading.Lock()

    def add_rule(self, interface, direction, action, protocol, source_mac, destination_mac, source_ip, destination_ip,
                 source_port,  destination_port):

        with self.acl_lock:
            self.rules.append({
                "interface": interface,
                "direction": direction,
                "action": action,
                "protocol": protocol,
                "source_mac": source_mac,
                "destination_mac": destination_mac,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port
            })

    def check_if_allowed(self, interface, direction, packet):

        src_mac = dst_mac = src_ip = dst_ip = protocol = src_port = dst_port = None

        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
        if ARP in packet:
            src_mac = packet[ARP].hwsrc
            dst_mac = packet[ARP].hwdst
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        if UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        if ICMP in packet:
            protocol = "ICMP"

        print("======================================\n")
        # Print info about packet
        print(f"Interface: {interface}, Direction: {direction}")
        print(f"Source MAC: {src_mac}, Destination MAC: {dst_mac}")
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Source Port: {src_port}, Destination Port: {dst_port}")

        number = 0

        print("Checking rules")

        with self.acl_lock:
            for rule in self.rules:
                print()
                print(f"Rule number: {number}")
                number += 1

                if rule["interface"] != interface:
                    print("Interface does not match")
                    continue
                if rule["direction"] != direction:
                    print("Direction does not match")
                    continue

                if rule["source_mac"] != src_mac and rule["source_mac"] != "any":
                    continue

                if rule["destination_mac"] != dst_mac and rule["destination_mac"] != "any":
                    continue

                if rule["source_ip"] != src_ip and rule["source_ip"] != "any":
                    continue

                if rule["destination_ip"] != dst_ip and rule["destination_ip"] != "any":
                    continue

                if rule["protocol"] != protocol and rule["protocol"] != "any":
                    continue

                if rule["source_port"] != src_port and rule["source_port"] != "any":
                    continue

                if rule["destination_port"] != dst_port and rule["destination_port"] != "any":
                    continue

                if rule["action"] == "allow":
                    print("Action is allow")
                    return True

                else:
                    print(f"Destination mac: {dst_mac} !!! DENIED")
                    print("Action is deny")
                    return False

        return False

    def get_rules(self):
        with self.acl_lock:
            return self.rules

    def print_rules(self):
        with self.acl_lock:
            print("Access Control List:")
            for rule in self.rules:
                print(rule)
            print("======================================\n")


    def delete_rule_by_index(self, index):
        with self.acl_lock:
            if index < len(self.rules):
                del self.rules[index]
                print(f"Rule number {index} was deleted.")
            else:
                print(f"Rule number {index} does not exist.")

    def delete_all_rules(self):
        with self.acl_lock:
            self.rules.clear()
            print("All rules were deleted.")

