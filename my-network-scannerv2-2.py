from scapy.all import Ether, ARP, srp
import re
import socket
#initialize target IP variable and valid range checker
target_ip = ARP()
valid_ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
#initialize broadcast variable (router destination)
broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
#initialize array of clients
clients = []



#main laucher function
def main():
    while True:
        get_current_ip()
        input_range = input("Enter IP Range (EX: 10.71.71.1/24): ")
        if valid_ip_pattern.search(input_range):
            print("Valid Range Entered. Processing...")
            target_ip.pdst = input_range
            break
        print("Invalid Range please try again.")
    send_packets()
    display_clients()
    

def get_current_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    print("Your current IP is: " + s.getsockname()[0])
    s.close()

def send_packets():
    packet = broadcast / target_ip
    client = srp(packet, timeout = 1)[0]
    for sent, received in client:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

def display_clients():
    print()
    print("No. |\tDevice Name     |\tIP Adddress     |\tMAC Address        |")
    print("____|\t________________|\t________________|\t___________________|")
    print()
    for client in clients:
        try:  
            print("{}\t{:20}\t{:16}\t{:16}".format(clients.index(client), socket.gethostbyaddr(client['ip'])[0], client['ip'], client['mac']))
            print("-"*76)
        except:
            print("{}\t{:20}\t{:16}\t{:16}".format(clients.index(client), "Unknown-Host", client['ip'], client['mac']))
            print("-"*76)

if __name__=="__main__":
    main()
