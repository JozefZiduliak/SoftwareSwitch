import threading
from Switch_GUI import SwitchGUI
from SwitchLogic import Switch


def main():

    # switch = Switch()
    # gui = SwitchGUI(switch)
    #
    # gui.run()

    #gui = SwitchGUI()
    switch = Switch()

    # Start the threads that sniff, handle and forward the packets
    sniffing_thread1 = threading.Thread(target=switch.start_listening, args=("eth0", "eth1"))
    sniffing_thread2 = threading.Thread(target=switch.start_listening, args=("eth1", "eth0"))

    sniffing_thread1.start()
    sniffing_thread2.start()



    # Start the GUI
    #gui.run()


if __name__ == "__main__":
    main()


