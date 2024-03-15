class MacAddressTable:

    def __init__(self):
        self.table = {}

    def add_entry(self, mac_address, timer, interface):
        self.table[mac_address] = {
            "timer": timer,
            "interface": interface
        }

    # Return mac address table
    def get_table(self):
        return self.table

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

    # Clear the mac address table
    def clear_table(self):
        self.table.clear()
