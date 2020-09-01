import subprocess
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its mac_address.")
    parser.add_option("-m", "--mac", dest="new_mac", help="New mac address.")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please provide the interface, use --help for more info.")
    if not options.new_mac:
        parser.error("[-] Please provide the new mac, use --help for more info.")
    return options

def change_mac(interface, new_mac):
    print("[+] Changing the mac address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


options = get_arguments()
change_mac(options.interface, options.new_mac)
