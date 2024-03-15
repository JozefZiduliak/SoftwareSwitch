import tkinter as tk
from tkinter import ttk
from SwitchLogic import Switch
import threading
import time

class SwitchGUI:
    def __init__(self, switch):
        # Vytvorenie hlavného okna
        self.root = tk.Tk()
        self.width = 1300
        self.height = 600
        self.root.geometry(f'{self.width}x{self.height}')

        # Nadpis
        self.setup_title()

        self.setup_timer_input_field()

        # Inicializácia premenných pre dopravu a ich nastavenie
        self.setup_traffic_variables()

        # Tlačidlá
        self.setup_buttons()

        # Interface labels a entry fields
        self.setup_interface_entries()

        # Protokoly a ich zobrazenie
        self.setup_protocols_display()

        # MAC adresa tabuľka
        self.setup_mac_table()

        # Reference for the switch
        self.switch = switch

    def setup_title(self):
        nadpis = tk.Label(self.root, text="PSIP L2 SWITCH", font=('Arial', 24))
        nadpis.pack(pady=(10, 20))

    def setup_traffic_variables(self):
        self.incoming_traffic_interface1 = [tk.IntVar(value=0) for _ in range(9)]
        self.outgoing_traffic_interface1 = [tk.IntVar(value=0) for _ in range(9)]
        self.incoming_traffic_interface2 = [tk.IntVar(value=0) for _ in range(9)]
        self.outgoing_traffic_interface2 = [tk.IntVar(value=0) for _ in range(9)]
        #self.incoming_traffic_interface1[8].set(20)  # Príklad zmeny hodnoty

    def setup_buttons(self):
        tk.Button(self.root, text="Start", font=('Arial', 10), command=self.start_action).place(x=520, y=50)
        tk.Button(self.root, text="Stop", font=('Arial', 10), command=self.start_action).place(x=740, y=50)
        tk.Button(self.root, text="Refresh Interface list", font=('Arial', 10), command=self.start_action).place(x=585, y=50)
        tk.Button(self.root, text="Clear", font=('Arial', 10), command=self.clear_mac_table).place(x=350, y=350)


    # Input fields and text above them
    # def setup_interface_entries(self):
    #     tk.Label(self.root, text="Interface 1", font=('Arial', 18)).place(x=10, y=10)
    #     tk.Entry(self.root, font=('Arial', 18)).place(x=10, y=50, width=200)
    #     tk.Label(self.root, text="Interface 2", font=('Arial', 18)).place(x=self.width - 210, y=10)
    #     tk.Entry(self.root, font=('Arial', 18)).place(x=self.width - 210, y=50, width=200)

    def setup_interface_entries(self):
        tk.Label(self.root, text="Interface 1", font=('Arial', 18)).place(x=10, y=10)
        self.interface1_entry = tk.Entry(self.root, font=('Arial', 18))
        self.interface1_entry.place(x=10, y=50, width=200)

        tk.Label(self.root, text="Interface 2", font=('Arial', 18)).place(x=self.width - 210, y=10)
        self.interface2_entry = tk.Entry(self.root, font=('Arial', 18))
        self.interface2_entry.place(x=self.width - 210, y=50, width=200)

    def setup_timer_input_field(self):
        tk.Label(self.root, text="Timer:", font=('Arial', 18)).place(x=830, y=350)  # Adjust the position as needed
        self.timer_entry = tk.Entry(self.root, font=('Arial', 18))
        self.timer_entry.place(x=900, y=350, width=50)  # Adjust the position as needed


    def setup_protocols_display(self):
        protocols = ["Ethernet II", "IP", "ARP", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "Total"]
        for i, protocol in enumerate(protocols):
            tk.Label(self.root, text=protocol, font=('Arial', 14)).place(x=120, y=120 + i * 30)
            tk.Label(self.root, textvariable=self.incoming_traffic_interface1[i], font=('Arial', 14)).place(x=50, y=120 + i * 30)
            tk.Label(self.root, textvariable=self.outgoing_traffic_interface1[i], font=('Arial', 14)).place(x=250, y=120 + i * 30)
            tk.Label(self.root, text=protocol, font=('Arial', 14)).place(x=1100, y=120 + i * 30)
            tk.Label(self.root, textvariable=self.outgoing_traffic_interface2[i], font=('Arial', 14)).place(x=1230, y=120 + i * 30)
            tk.Label(self.root, textvariable=self.incoming_traffic_interface2[i], font=('Arial', 14)).place(x=1040, y=120 + i * 30)

    def setup_mac_table(self):
        self.mac_table = ttk.Treeview(self.root)
        self.mac_table["columns"] = ("mac_address", "timer", "port")
        self.mac_table.column("#0", width=0, stretch=tk.NO)
        self.mac_table.column("mac_address", anchor=tk.CENTER, width=200)
        self.mac_table.column("timer", anchor=tk.CENTER, width=200)
        self.mac_table.column("port", anchor=tk.CENTER, width=200)
        self.mac_table.heading("#0", text="", anchor=tk.CENTER)
        self.mac_table.heading("mac_address", text="MAC address", anchor=tk.CENTER)
        self.mac_table.heading("timer", text="Timer", anchor=tk.CENTER)
        self.mac_table.heading("port", text="Port", anchor=tk.CENTER)
        self.mac_table.place(x=350, y=150, width=600, height=200)
        #self.add_record_to_mac_table('00:0a:95:9d:68:16', '300', '1')

    def add_record_to_mac_table(self, mac_address, timer, port):
        self.mac_table.insert('', 'end', values=(mac_address, timer, port))


    # Method that removes all entries from mac table in GUI, so new ones can be added
    def refresh_mac_table(self):
        for i in self.mac_table.get_children():
            self.mac_table.delete(i)

        # Remove all entries from data strcutures in SwitchLogic
        #self.switch.refresh_mac_table()

    def clear_mac_table(self):
        self.refresh_mac_table()
        self.switch.clear_mac_table()

    def start_action(self):
        # interface1 = self.interface1_entry.get()
        # interface2 = self.interface2_entry.get()

        # sniffing_thread1 = threading.Thread(target=self.switch.start_listening, args=(interface1, interface2))
        # sniffing_thread2 = threading.Thread(target=self.switch.start_listening, args=(interface2, interface1))

        # sniffing_thread1 = threading.Thread(target=self.switch.start_listening, args=("eth0", "eth1"))
        # sniffing_thread2 = threading.Thread(target=self.switch.start_listening, args=("eth1", "eth0"))
        #
        # sniffing_thread1.start()
        # sniffing_thread2.start()

        interface1 = self.interface1_entry.get()
        interface2 = self.interface2_entry.get()

        interface1 = "Realtek USB GbE Family Controller #11"
        interface2 = "Realtek USB GbE Family Controller"

        self.switch.set_interface_name(interface1, interface2)

        # Start the threads that sniff, handle and forward the packets
        sniffing_thread1 = threading.Thread(target=self.switch.start_listening, args=("eth0", "eth1"))
        sniffing_thread2 = threading.Thread(target=self.switch.start_listening, args=("eth1", "eth0"))

        updating_thread = threading.Thread(target=self.update_traffic)
        decrementing_thread = threading.Thread(target=self.switch.decrement_mac_table_timer)

        sniffing_thread1.start()
        sniffing_thread2.start()
        updating_thread.start()
        decrementing_thread.start()

    def run(self):
        self.root.mainloop()

    def update_traffic(self):

        while True:  # Assuming stop_threads is a flag to stop threads
            # Updating incoming stats for interface 1
            interface1_incoming_stats = self.switch.get_traffic_stats("interface1", "Incoming")


            for i in range(9):
                self.incoming_traffic_interface1[i].set(interface1_incoming_stats[i])

            # Updating outgoing stats for interface 1
            interface1_outgoing_stats = self.switch.get_traffic_stats("interface1", "Outgoing")
            for i in range(9):
                self.outgoing_traffic_interface1[i].set(interface1_outgoing_stats[i])

            # Updating incoming stats for interface 2
            interface2_incoming_stats = self.switch.get_traffic_stats("interface2", "Incoming")
            for i in range(9):
                self.incoming_traffic_interface2[i].set(interface2_incoming_stats[i])

            # Updating outgoing stats for interface 2
            interface2_outgoing_stats = self.switch.get_traffic_stats("interface2", "Outgoing")
            for i in range(9):
                self.outgoing_traffic_interface2[i].set(interface2_outgoing_stats[i])

            time.sleep(1)  # Pause for a while before the next update

            # Remove old entries from the mac address table

            self.refresh_mac_table()
            mac_address_table = self.switch.return_mac_table()

            for mac_address, entry in mac_address_table.items():
                self.add_record_to_mac_table(mac_address, entry['timer'], entry['interface'])



# if __name__ == "__main__":
#     app = SwitchGUI()
#     app.run()
