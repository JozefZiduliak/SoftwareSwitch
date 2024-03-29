import psutil

def list_network_interfaces():
    """
    List all network interfaces and their operational status.
    """
    interface_stats = psutil.net_if_stats()
    for interface_name, stats in interface_stats.items():
        status = "up" if stats.isup else "down"
        print(f"Interface: {interface_name}, Status: {status}")

if __name__ == "__main__":
    list_network_interfaces()
