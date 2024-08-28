import scapy.all as scapy
import logging
from scapy.layers import http

# Setup logging
logging.basicConfig(filename='sniffer.log', level=logging.INFO, format='%(asctime)s - %(message)s')


def process_packet(packet):
    # Process each packet and extract specific details based on its type.

    # if packet.haslayer(scapy.Ether):
    #     eth_layer = packet[scapy.Ether]
    #     src_mac = eth_layer.src
    #     dst_mac = eth_layer.dst
    #     logging.info(f"Ethernet Frame: {src_mac} -> {dst_mac}")

    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            logging.info(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if packet.haslayer(scapy.UDP):
            udp_layer = packet[scapy.UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            logging.info(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if packet.haslayer(http.HTTPRequest):
            http_layer = packet[http.HTTPRequest]
            logging.info(f"HTTP Request: {src_ip} -> {http_layer.Host.decode()}{http_layer.Path.decode()}")
            if b'suspicious.com' in http_layer.Host:
                logging.warning(f"Alert: Suspicious domain detected from {src_ip}")

    print(packet.show())


def sniffing(interface):
    # Start sniffing on the specified interface and process each captured packet.
    scapy.sniff(iface=interface, store=False, prn=process_packet)


# Start sniffing
sniffing('WiFi 2')





