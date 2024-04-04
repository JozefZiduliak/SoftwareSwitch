import tkinter as tk
from tkinter import ttk
from SwitchLogic import Switch
import threading
import time
from SwitchACL import AccesControlList

class SwitchGUI:
    def __init__(self):
        # Vytvorenie hlavného okna
        self.root = tk.Tk()
        self.width = 1300
        self.height = 750
        self.root.geometry(f'{self.width}x{self.height}')
        self.timer_var = None
        self.interface1_entry = None
        self.timer_value = 0
        self.change_occured = None
        self.acl = AccesControlList()

        self.timer_entry = None
        self.interface_entry = None

        self.root.title("Software Switch")


        # Nadpis
        self.setup_title()

        #self.setup_timer_input_field()

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

        self.acl = AccesControlList()

        # Reference for the switch
        self.switch = Switch(self.acl)

        # Timer input field
        self.setup_timer_input_field()

        # ACL delete input field
        self.setup_acl_delete_input_field()

        # ACL entry fields
        self.setup_acl_entry_fields()

        # ACL table
        self.setup_acl_table()


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
        tk.Button(self.root, text="UPDATE", font=('Arial', 10), command=self.update_timer).place(x=885, y=350)  # Adjust the positio
        tk.Button(self.root, text="Reset Stats 1", font=('Arial', 10),
                  command=self.reset_stats_interface_1).place(x=100, y=400)
        tk.Button(self.root, text="Reset Stats 2", font=('Arial', 10),
                  command=self.reset_stats_interface_2).place(x=1090, y=400)
        tk.Button(self.root, text="Add", font=('Arial', 10), command=self.add_acl_rule).place(x=1255, y=680)
        tk.Button(self.root, text="Delete", font=('Arial', 10), command=self.delete_acl_rule).place(x=1145, y=680)
        tk.Button(self.root, text="Clear All", font=('Arial', 10), command=self.delete_all_acl_rules).place(x=1195, y=680)


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

        tk.Label(self.root, text="TIMER VALUE:", font=('Arial', 15)).place(x=670, y=350)

        self.timer_entry = tk.Entry(self.root, font=('Arial', 15))
        self.timer_entry.place(x=835, y=350, width=50)  # Adjust the position and width as needed


    def setup_acl_entry_fields(self):
        tk.Label(self.root, text="Interface", font=('Arial', 11)).place(x=10, y=650)

        self.interface_entry = tk.Entry(self.root, font=('Arial', 11))
        self.interface_entry.place(x=70, y=650, width=70)

        tk.Label(self.root, text="Direction", font=('Arial', 11)).place(x=140, y=650)

        self.direction_entry = tk.Entry(self.root, font=('Arial', 11))
        self.direction_entry.place(x=205, y=650, width=30)

        tk.Label(self.root, text="Action", font=('Arial', 11)).place(x=235, y=650)

        self.action_entry = tk.Entry(self.root, font=('Arial', 11))
        self.action_entry.place(x=280, y=650, width=40)

        tk.Label(self.root, text="Protocol", font=('Arial', 11)).place(x=320, y=650)

        self.protocol_entry = tk.Entry(self.root, font=('Arial', 11))
        self.protocol_entry.place(x=380, y=650, width=40)

        tk.Label(self.root, text="Src MAC", font=('Arial', 11)).place(x=420, y=650)

        self.source_mac_entry = tk.Entry(self.root, font=('Arial', 11))
        self.source_mac_entry.place(x=485, y=650, width=120)


        tk.Label(self.root, text="Dst MAC", font=('Arial', 11)).place(x=605, y=650)

        self.destination_mac_entry = tk.Entry(self.root, font=('Arial', 11))
        self.destination_mac_entry.place(x=670, y=650, width=120)


        tk.Label(self.root, text="Src IP", font=('Arial', 11)).place(x=790, y=650)

        self.source_ip_entry = tk.Entry(self.root, font=('Arial', 11))
        self.source_ip_entry.place(x=835, y=650, width=90)

        tk.Label(self.root, text="Dst IP", font=('Arial', 11)).place(x=930, y=650)

        self.destination_ip_entry = tk.Entry(self.root, font=('Arial', 11))

        self.destination_ip_entry.place(x=975, y=650, width=90)

        tk.Label(self.root, text="Src Port", font=('Arial', 11)).place(x=1070, y=650)

        self.source_port_entry = tk.Entry(self.root, font=('Arial', 11))
        self.source_port_entry.place(x=1130, y=650, width=50)

        tk.Label(self.root, text="Dst Port", font=('Arial', 11)).place(x=1180, y=650)


        self.destination_port_entry = tk.Entry(self.root, font=('Arial', 11))
        self.destination_port_entry.place(x=1240, y=650, width=50)

    def setup_acl_delete_input_field(self):
        tk.Label(self.root, text="DELETE ID:", font=('Arial', 13)).place(x=995, y=685)

        self.acl_entry = tk.Entry(self.root, font=('Arial', 13))
        self.acl_entry.place(x=1090, y=685, width=50)

    def add_acl_rule(self):
        interface = self.interface_entry.get()
        direction = self.direction_entry.get()
        action = self.action_entry.get()
        protocol = self.protocol_entry.get()
        source_mac = self.source_mac_entry.get()
        destination_mac = self.destination_mac_entry.get()
        source_ip = self.source_ip_entry.get()
        destination_ip = self.destination_ip_entry.get()
        source_port = self.source_port_entry.get()
        destination_port = self.destination_port_entry.get()

        if source_port != 'any':
            source_port = int(source_port)
        if destination_port != 'any':
            destination_port = int(destination_port)

        self.acl.add_rule(interface, direction, action, protocol, source_mac, destination_mac, source_ip, destination_ip, source_port, destination_port)
        # self.acl.add_rule("Ethernet 0", "out", "allow", "any", "any", "any", "any", "any", "any", "any")

        #self.acl.add_rule("Ethernet 0", "out", "allow", "any", "any", "any", "any", "192.168.0.2", "any", "any")
        #self.acl.add_rule("Ethernet 0", "in", "allow", "any", "any", "any", "any", "any", "any", "any")

        #self.acl.add_rule("Ethernet 1", "out", "allow", "any", "any", "any", "any", "any", "any", "any")
        #self.acl.add_rule("Ethernet 1", "in", "allow", "any", "any", "any", "any", "any", "any", "any")

    def delete_acl_rule(self):
        acl_id = self.acl_entry.get()
        self.acl.delete_rule_by_index(int(acl_id))

    def delete_all_acl_rules(self):
        self.acl.delete_all_rules()

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

    # Method to set up the ACL rules table
    def setup_acl_table(self):
        # Creating a Treeview widget
        self.acl_table = ttk.Treeview(self.root)
        # Defining columns
        self.acl_table["columns"] = ("interface", "direction", "action", "protocol",
                                     "source_mac", "destination_mac", "source_ip", "destination_ip",
                                     "source_port", "destination_port")
        # Configuring the columns
        self.acl_table.column("#0", width=0, stretch=tk.NO)  # Phantom column for ID
        self.acl_table.column("interface", anchor=tk.CENTER, width=80)
        self.acl_table.column("direction", anchor=tk.CENTER, width=80)
        self.acl_table.column("action", anchor=tk.CENTER, width=80)
        self.acl_table.column("protocol", anchor=tk.CENTER, width=80)
        self.acl_table.column("source_mac", anchor=tk.CENTER, width=120)
        self.acl_table.column("destination_mac", anchor=tk.CENTER, width=120)
        self.acl_table.column("source_ip", anchor=tk.CENTER, width=100)
        self.acl_table.column("destination_ip", anchor=tk.CENTER, width=100)
        self.acl_table.column("source_port", anchor=tk.CENTER, width=80)
        self.acl_table.column("destination_port", anchor=tk.CENTER, width=80)

        # Configuring the column headings
        self.acl_table.heading("#0", text="", anchor=tk.CENTER)
        self.acl_table.heading("interface", text="Interface", anchor=tk.CENTER)
        self.acl_table.heading("direction", text="Direction", anchor=tk.CENTER)
        self.acl_table.heading("action", text="Action", anchor=tk.CENTER)
        self.acl_table.heading("protocol", text="Protocol", anchor=tk.CENTER)
        self.acl_table.heading("source_mac", text="Src MAC", anchor=tk.CENTER)
        self.acl_table.heading("destination_mac", text="Dst MAC", anchor=tk.CENTER)

        self.acl_table.heading("source_ip", text="Src IP", anchor=tk.CENTER)
        self.acl_table.heading("destination_ip", text="Dst IP", anchor=tk.CENTER)
        self.acl_table.heading("source_port", text="Src Port", anchor=tk.CENTER)
        self.acl_table.heading("destination_port", text="Dst Port", anchor=tk.CENTER)

        # Placing the ACL table on the GUI
        self.acl_table.place(x=10, y=450, width=1280, height=200)  # Adjust the position and size as needed

    def add_record_to_mac_table(self, mac_address, timer, port):
        self.mac_table.insert('', 'end', values=(mac_address, timer, port))


    # Method that removes all entries from mac table in GUI, so new ones can be added
    def refresh_mac_table(self):
        for i in self.mac_table.get_children():
            self.mac_table.delete(i)

        mac_address_table = self.switch.return_mac_table()

        for mac_address, entry in mac_address_table.items():
            self.add_record_to_mac_table(mac_address, entry['timer'], entry['interface'])

    def refresh_acl_table(self):

        for i in self.acl_table.get_children():
            self.acl_table.delete(i)

        acl_rules = self.acl.get_rules()

        for rule in acl_rules:
            self.add_entry_to_acl_table(rule)


        # Remove all entries from data strcutures in SwitchLogic
        #self.switch.refresh_mac_table()

    def clear_mac_table(self):
        self.refresh_mac_table()
        self.switch.clear_mac_table()

    def update_timer(self):
        timer_value = self.timer_entry.get()
        print("Timer value changed to:", timer_value)
        self.switch.set_timer_value(int(timer_value))

    def add_entry_to_acl_table(self, rule):
        self.acl_table.insert('', 'end', values=(rule['interface'], rule['direction'], rule['action'], rule['protocol'],
                                                 rule['source_mac'], rule['destination_mac'], rule['source_ip'],
                                                 rule['destination_ip'], rule['source_port'], rule['destination_port']))

    def start_action(self):

        #self.acl.add_rule("Ethernet 0", "out", "deny", "any", "any", "any", "any", "192.168.0.2", "any", "any")
        #self.acl.add_rule("Ethernet 1", "in", "deny", "ICMP", "any", "7c:57:58:3e:d2:3d", "any", "any", "any", "any")

        #self.acl.add_rule("Ethernet 0", "in", "deny", "any", "any", "any", "192.168.0.2", "any", "any", 8000)

        interface1 = self.interface1_entry.get()
        interface2 = self.interface2_entry.get()

        interface1 = "Realtek USB GbE Family Controller #11"
        interface2 = "Realtek USB GbE Family Controller"

        # Potentionally cause of issue
        self.switch.set_interface_name(interface1, interface2)

        # Start the threads that sniff, handle and forward the packets
        sniffing_thread1 = threading.Thread(target=self.switch.start_listening, args=("Ethernet 0",))
        sniffing_thread2 = threading.Thread(target=self.switch.start_listening, args=("Ethernet 1",))

        # ZMENA
        #monitoring_thread = threading.Thread(target=self.switch.check_interface_status)

        updating_thread = threading.Thread(target=self.update_traffic)
        decrementing_thread = threading.Thread(target=self.switch.decrement_mac_table_timer)

        sniffing_thread1.start()
        sniffing_thread2.start()
        updating_thread.start()
        decrementing_thread.start()

        #ZMENA
        #monitoring_thread.start()

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

            # Remove old entries from the mac address table
            self.refresh_mac_table()

            # ACL Logic
            self.refresh_acl_table()

            time.sleep(1)  # Pause for a while before the next update


    def reset_stats_interface_1(self):
        self.switch.clear_stats("interface1")

    def reset_stats_interface_2(self):
        self.switch.clear_stats("interface2")

if __name__ == "__main__":
    app = SwitchGUI()
    app.run()
