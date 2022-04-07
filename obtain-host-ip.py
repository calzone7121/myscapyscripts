from scapy.all import *
import socket
import os

data = []
valid_ip_pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

def main():
    while True:
        print("="*8 + "Select Option" + "="*8)
        print("1) Add Host/IP")
        print("2) Show current data")
        print("99) Exit")
        choice =  int(input("Select: "))
        if choice == 1:
            cls()
            get_data()
            continue
        elif choice == 2:
            cls()
            print_data()
            continue
        elif choice == 99:
            cls()
            exit()
        else:
            cls()
            print("Error, invalid option")


def get_data():
    while True:
        user_input = input("Enter IP address or Domain name: ")
        host_string = ""
        try:
            if valid_ip_pattern.search(user_input):
                host_ip = user_input
                host_string = socket.gethostbyaddr(user_input)
                data.append({'hostname': host_string, 'hostip': host_ip})
                break
            else:
                host_string = user_input
                host_ip = socket.gethostbyname(user_input)
                data.append({'hostname': host_string, 'hostip': host_ip})
                break
        except:
            cls()
            print("Error, invalid input please try again")

def print_data():
    print()
    print("No. |\tHostname      |\t\tIP Address        |")
    print("____|\t______________|\t\t__________________|")
    print()
    for x in data:
        try:
            print("{}\t{:20}\t{:16}".format(data.index(x), x['hostname'], x['hostip']))
            print("-"*50)
        except:
            print("{}\t{:20}\t{:16}".format(data.index(x), "Unknown Hostname", x['hostip']))
            print("-"*50)

def cls():
    os.system('cls' if os.name=='nt' else 'clear')



if __name__=="__main__":
    main()