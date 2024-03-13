import wmi
import time

def check_network_cable_status():
    c = wmi.WMI()
    for adapter in c.Win32_NetworkAdapter(NetConnectionStatus=2):
        if adapter.NetEnabled:
            print(f"{adapter.Name} is connected.")
        else:
            print(f"{adapter.Name} is disconnected.")

if __name__ == "__main__":
    print("Monitoring network cable status. Press Ctrl+C to stop.")
    try:
        while True:
            check_network_cable_status()
            time.sleep(5)  # Check every 5 seconds
    except KeyboardInterrupt:
        print("Stopped by the user.")
