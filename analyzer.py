from scapy.all import rdpcap, TCP, UDP, ICMP , IP


packets = rdpcap("network_traffic_example.pcap")
packet_amount = len(packets)
print(f"Total packets: {packet_amount}")

def count_protocols(packets):
    tcp_count = 0
    udp_count = 0
    icmp_count =0 
    
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_count += 1
        elif packet.haslayer(UDP):
            udp_count += 1
        elif packet.haslayer(ICMP):
            icmp_count += 1
    return tcp_count, udp_count, icmp_count

def analyze_ips(packets):
    ip_cont = 0
    ip_count = {}
    for packet in packets:
        if packet.haslayer(IP):
            source = packet[IP].src
            if source in ip_count:
                ip_count[source] += 1
            else:
                ip_count[source] = 1 

    return ip_count

           
    


tcp_count, udp_count, icmp_count = count_protocols(packets)
print(f"TCP packets: {tcp_count}")
print(f"UDP packets: {udp_count}")
print(f"ICMP packets: {icmp_count}")

print(analyze_ips(packets))



