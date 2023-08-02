



from scapy.all import sniff
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.all import wrpcap

def packetHandler(packet):
    if packet.haslayer(Dot11ProbeReq):
        print("hi guys")

probe_requests = []
sniff(iface='wlan0mon', prn=lambda x: probe_requests.append(x) if x.haslayer(Dot11ProbeReq) else None)
wrpcap('second_try.pcap', probe_requests)

