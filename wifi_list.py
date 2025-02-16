from scapy.all import ARP, Ether, srp

def get_mac():
    target_ip = "192.168.1.1/24"  # เปลี่ยนให้ตรงกับ network
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)[0]
    
    for sent, received in result:
        print(f"IP: {received.psrc}, MAC: {received.hwsrc}")
    return result[0][1].hwsrc if result else None

selected_mac = get_mac()
print(f"Selected MAC: {selected_mac}")
