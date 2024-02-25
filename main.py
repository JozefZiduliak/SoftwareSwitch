from scapy.all import *
#import SwitchGUI
from SwitchGUI import GUIApplication
from SwitchLogic import Switch

from scapy.layers.l2 import Ether
import threading


# app = GUIApplication()
# app.add_mac_entry("00:00:00:00:00:02", "00:00:10", "2")
# app.window.mainloop()

#show_interfaces()

def handle_packet(packet):

    print("======================================================================================")
    # If it has ether layer
    if Ether in packet:
        #  Saves src and destination mac adress
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        # Prints src and dst MAC adress
        print(f"Zdrojová MAC adresa: {src_mac}, Cieľová MAC adresa: {dst_mac}")
    else: # If it has no ether layer

        print("Packet has no ether layer")

    # Prints more details about packet
    #packet.show()


#sniff(filter="dst host 10.6.0.7", prn=handle_packet)



def main():
    # interface_name_1 = "Realtek USB GbE Family Controller"
    # sniff(iface=interface_name_1, prn=handle_packet)

    # switch = Switch()
    #
    # thread1 = threading.Thread(target=switch.start_listening, args=("eth0", "eth1"))
    # thread2 = threading.Thread(target=switch.start_listening, args=("eth1", "eth0"))
    #
    # thread1.start()
    # thread2.start()


    # print(switch.switch_table)
    # switch.show_stats()

    app = GUIApplication()
    app.add_mac_entry("00:00:00:00:00:02", "00:00:10", "2")
    app.window.mainloop()


if __name__ == "__main__":
    main()


