import scapy.all as scapy
import socket
import sys
import pyfiglet
from termcolor import cprint

result = pyfiglet.figlet_format("SOSAKORNUT")
cprint(result, "cyan", "on_blue")

privateIp = sys.argv[1]

def scanning(ip):
    global ip_addresses
    global mac_addresses
    global num
    ip_addresses = []
    mac_addresses = []
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    for element in answered_list:
        ip_addresses.append(element[1].psrc)
        mac_addresses.append(element[1].hwsrc)
        cprint(element[1].psrc, "cyan")
        cprint(element[1].hwsrc, "cyan")

scanning(privateIp)
num = -1

while True:
    try:
        num += 1
        cprint(f"Scanning for {ip_addresses[num]} {mac_addresses[num]}", "yellow")
        for port in range(0, 1000):
            try:
                s = socket.socket()
                s.connect((ip_addresses[num], port))
                cprint(f"[$] PORT {port} IS OPEN", "green")
            except:
                pass

    except IndexError:
        exit(0)
    
    

