import datetime
from scapy.all import sniff, wrpcap
from scapy.layers.dot11 import Dot11ProbeReq

probe_requests = []

timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

sniff(iface='wlan0mon', prn=lambda x: probe_requests.append(x) if x.haslayer(Dot11ProbeReq) else None, timeout=300)
wrpcap('second_try_'+timestamp+'.pcap', probe_requests)

