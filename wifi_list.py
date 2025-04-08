from scapy.all import ARP, Ether, srp

def scan_network(network_range="192.168.1.1/24"):
    """สแกนหา IP และ MAC Address ในเครือข่ายที่กำหนด"""
    # สร้างแพ็กเก็ต ARP Request
    arp_request = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # ส่ง Broadcast
    packet = ether / arp_request

    # ส่งแพ็กเก็ตและรับคำตอบ
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

# กำหนดช่วง IP ที่ต้องการสแกน
network_range = "192.168.1.1/16"

# เรียกใช้ฟังก์ชัน
devices = scan_network(network_range)

# แสดงผลลัพธ์
print("IP Address\t\tMAC Address")
print("-" * 40)
for device in devices:
    print(f"{device['ip']}\t{device['mac']}")
