from scapy.all import ICMP, TCP, RandShort, sr1, IP
import re
import os
import socket

valid_ip_pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

def main():
    target_address, target_string = get_target()
    port_target = get_port()
    cls()
    while True:
        print("HOSTNAME/IP: " + target_string + " >> " + target_address)
        print("PORT: " + str(port_target))
        print("="*25)
        print("1) Scan port")
        print("2) Change Hostname/IP")
        print("3) Change target port")
        print("99) Exit")
        choice = int(input("Select Option: "))
        if choice == 1:
            cls()
            port_scan(target_address, port_target)
            continue
        elif choice == 2:
            cls()
            target_address, target_string = get_target()
            continue
        elif choice == 3:
            cls()
            port_target = get_port()
            continue
        elif choice == 99:
            cls()
            exit()
        else:
            cls()
            print("Error, please choose a valid option")
            continue

def get_port():
    while True:
        try:
            port_target = int(input("Enter port number to scan: "))
            return port_target
        except:
            print("Error, please try again")


def get_target():
    while True:
        host_string = ""
        user_input = input("Enter target by hostname OR IP address (EX: www.----.com or x.x.x.x): ")
        if valid_ip_pattern.search(user_input):
            target = user_input
            return target, host_string
        else:
            try:
                target = socket.gethostbyname(user_input)
                host_string = user_input
                return target, host_string
            except:
                print("Error, invalid input try again")
    
def cls():
    os.system('cls' if os.name=='nt' else 'clear')

def print_ports(port, state):
    print("%s | %s" % (port, state))
    print("")

def port_scan(target, ports):
    print("syn scan on, %s with ports %s" % (target, ports))
    sport = RandShort()
    pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=ports, flags="S"), timeout=1, verbose=0)
    if pkt != None:
        if pkt.haslayer(TCP):
            if pkt[TCP].flags == 20:
                print_ports(ports, "Closed")
                #pass
            elif pkt[TCP].flags == 18:
                print_ports(ports, "Open")
            else:
                print_ports(ports, "TCP packet resp / filtered")
        elif pkt.haslayer(ICMP):
            print_ports(ports, "ICMP resp / filtered")
        else:
            print_ports(ports, "Unknown resp")
            print(pkt.summary())
    else:
        print_ports(ports, "Unanswered")



if __name__=="__main__":
    main()