from scapy.all import ARP, Ether, srp

def scan_local_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    ip_range = "192.168.1.1/24" 
    devices = scan_local_network(ip_range)

    print("Bulunan Cihazlar:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    main()