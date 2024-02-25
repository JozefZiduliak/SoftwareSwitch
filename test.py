import tkinter as tk
from tkinter import ttk

# Vytvoríme hlavné okno aplikácie
root = tk.Tk()
root.title("PSIP L2 Switch GUI")

# Funkcia pre resetovanie všetkých polí
def reset_fields():
    for interface in interfaces:
        for direction in ("In", "Out"):
            for protocol in protocols:
                interface[direction][protocol].set("0")
    mac_table.delete(*mac_table.get_children())

# Protokoly, ktoré chceme zobraziť
protocols = ["Ethernet II", "IP", "ARP", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "Total"]

# Vytvoríme dve rozhrania s príslušnými poliami pre prichádzajúcu a odchádzajúcu prevádzku
interfaces = []
for i in range(1, 3):
    frame = tk.LabelFrame(root, text=f"Interface {i}", padx=5, pady=5)
    frame.grid(row=0, column=i-1, padx=10, pady=10, sticky="nsew")

    # Vytvoríme vnútornú štruktúru pre rozhranie
    interface = {"In": {}, "Out": {}}
    for row, protocol in enumerate(protocols):
        for col, direction in enumerate(("In", "Out")):
            label = tk.Label(frame, text=protocol)
            label.grid(row=row, column=2*col, sticky="e")

            # Tu budeme zobrazovať hodnoty
            value = tk.StringVar(value="0")
            value_label = tk.Label(frame, textvariable=value, width=5, relief="sunken")
            value_label.grid(row=row, column=2*col+1, padx=5, pady=2)

            interface[direction][protocol] = value

    interfaces.append(interface)

    # Pridáme tlačidlo pre reset
    reset_button = tk.Button(frame, text="Reset", command=reset_fields)
    reset_button.grid(row=len(protocols), column=0, columnspan=4, pady=5)

# Vytvoríme MAC tabuľku v strede
mac_frame = tk.LabelFrame(root, text="MAC Table", padx=5, pady=5)
mac_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

# Pomocou ttk.Treeview vytvoríme tabuľku
columns = ("MAC address", "Timer", "Port")
mac_table = ttk.Treeview(mac_frame, columns=columns, show="headings")
for col in columns:
    mac_table.heading(col, text=col)
    mac_table.column(col, width=100)
mac_table.pack(expand=True, fill="both")

# Rozloženie okna
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.columnconfigure(2, weight=1)
root.rowconfigure(0, weight=1)

# Spustíme hlavnú slučku Tkinter aplikácie
root.mainloop()
