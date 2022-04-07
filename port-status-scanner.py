# port scanner
from scapy.all import IP, TCP, UDP, RandShort, ICMP, sr1
import re
import os

valid_ip_pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

def main():
    target_ip = get_ip()
    port_range, port_string, show_flag = get_port_range()
    while True:
        print("="*6 + "MENU" + "="*6)
        print("IP: " + target_ip)
        print(port_string)
        print("Specific Ports: ")
        print("1) TCP/SYN Scan")
        print("2) UPD Scan")
        print("3) XMAS Scan")
        print("4) Change IP")
        print("5) Change Port Range")
        print(("99) Exit"))
        choice = int(input("Select Option: "))
        if choice == 1:
            cls()
            syn_scan(target_ip, port_range, show_flag)
            continue
        elif choice == 2:
            cls()
            udp_scan(target_ip, port_range, show_flag)
            continue
        elif choice == 3:
            cls()
            xmas_scan(target_ip, port_range, show_flag)
            continue
        elif choice == 4:
            cls()
            target_ip = get_ip()
            continue
        elif choice == 5:
            cls()
            port_range, port_string, show_flag = get_port_range()
            continue
        elif choice == 99:
            cls()
            exit()
        else:
            print("Invalid Option try again")
            continue

#get ip value
def get_ip():
    while True:
        input_range = input("Enter valid IP address (EX: 10.71.71.1): ")
        if valid_ip_pattern.search(input_range):
            print("Valid IP Entered")
            cls()
            return input_range
        print("Invalid IP please try again")

#set port values
def get_port_range():
    while True:
        print("="*6 + "Choose Port Input" + "="*6)
        print("1) Enter Port Range (wont show closed/unanswered ports)")
        print("2) Enter list of specific ports")
        choice = int(input("Select Option: "))
        if choice == 1:
            while True:    
                min_port = int(input("Enter Starting port number: "))
                if min_port > 0:
                    break
                else:
                    print("Error, starting port must be > 0")
            print("Current Port Range: [" + str(min_port) + " - x]")
            while True:
                max_port = int(input("Enter final port number: "))
                if(max_port >= min_port):
                    break
                else:
                    print("Error, Port must be larger than starting port")
            port_range = (min_port, max_port)
            flag = False
            port_string = "Port Range: ["+str(min_port)+"-"+str(max_port)+"] (wont show closed/unanswered ports)"
            cls()
            return port_range, port_string, flag
        elif choice == 2:
            while True:
                temp = input("Enter list of port numbers separated by a comma (EX: x,x,x,x,x): ")
                try:
                    port_list = [int(x) for x in temp.split(",")]
                    port_string = ("Ports: " + temp)
                    flag = True
                    break
                except:
                    print("Error, try again")
                    continue
            cls()
            return port_list, port_string, flag
        else:
            print("Error, choose an AVAILABLE option")
    

# output format # TODO make prettier 
def print_ports(port, state):
	print("%s | %s" % (port, state))

def cls():
    os.system('cls' if os.name=='nt' else 'clear')


# syn scan
def syn_scan(target, ports, flag):
    print("syn scan on, %s with ports %s" % (target, ports))
    sport = RandShort()
    for port in ports:
        pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                if (pkt[TCP].flags == 20) and (flag == True):
                    print_ports(port, "Closed")
                    #pass
                elif pkt[TCP].flags == 18:
                    print_ports(port, "Open")
                else:
                    print_ports(port, "TCP packet resp / filtered")
            elif pkt.haslayer(ICMP):
                print_ports(port, "ICMP resp / filtered")
            else:
                print_ports(port, "Unknown resp")
                print(pkt.summary())
        elif(flag == True):
            print_ports(port, "Unanswered")

# udp scan
def udp_scan(target, ports, flag):
    print("udp scan on, %s with ports %s" % (target, ports))
    for port in ports:
        pkt = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2, verbose=0)
        if pkt == None:
            print_ports(port, "Open / filtered")
        else:
            if pkt.haslayer(ICMP) and flag == True:
                print_ports(port, "Closed")
            elif pkt.haslayer(UDP):
                print_ports(port, "Open / filtered")
            elif (flag == True):
                print_ports(port, "Unknown")
                print(pkt.summary())

# xmas scan
def xmas_scan(target, ports, flag):
    print("Xmas scan on, %s with ports %s" %(target, ports))
    sport = RandShort()
    for port in ports:
        pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)
        if pkt != None:
            if pkt.haslayer(TCP):
                if pkt[TCP].flags == 20 and flag == True:
                    print_ports(port, "Closed")
                else:
                    print_ports(port, "TCP flag %s" % pkt[TCP].flag)
            elif pkt.haslayer(ICMP):
                print_ports(port, "ICMP resp / filtered")
            elif(flag == True):
                print_ports(port, "Unknown resp")
                print(pkt.summary())
        else:
            print_ports(port, "Open / filtered")

if __name__=="__main__":
    main()