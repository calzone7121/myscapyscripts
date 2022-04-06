import scapy.all as scapy
import re
import socket


#initialize target IP address range
target_ip = scapy.ARP()
#initialize destination target
broadcast = scapy.Ether()
#create ip range validation
valid_ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
#initialize array of clients
clients = []

#main function
def main():
    while True:
        get_current_ip()
        input_range = input("Enter IP Address Range (EX: 0.0.0.0/24): ")
        if valid_ip_pattern.search(input_range):
            target_ip.pdst = input_range
            print("Valid IP Address. Processing...")
            break
        print("Invalid IP range please try again.")
    send_packets()
    display_clients()

#Obtain current IP address for reference of range
def get_current_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    print("Your current IP is: " + s.getsockname()[0])
    s.close()

#Send packets to get info and populate clients array
def send_packets():
    broadcast.dst='ff:ff:ff:ff:ff:ff'
    packet = broadcast / target_ip
    client = scapy.srp(packet, timeout = 1)[0]
    for sent, received in client:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

#display clients information from clients array
def display_clients():
    print()
    print("No |\tIP Address     |\tMAC Address        |")
    print("___|\t_______________|\t___________________|")
    print()
    for client in clients:
        print("{}\t{}\t\t{}".format(clients.index(client), client['ip'], client['mac']))
        print("-"*52)

if __name__=="__main__":
    main()