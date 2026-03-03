from scapy.all import *

def packet_callback(packet):
    print("\n--packet captured--")
   # IP layer Info
    if packet.haslayer(IP):
        print("source IP:",packet[IP].src)
        print("destination IP:",packet[IP].dst)
  #TCP Info
    if packet.haslayer(TCP):
       print("protocol:TCP")
       print("source port:",packet[TCP].sport)
       print("destination port:",packet[TCP].dport)
  # UDP Info
    elif packet.haslayer(UDP):
        print("protocol:UDP")
        print("source port:",packet[UDP].sport)
        print("destination port:",packet[UDP].dport)
  #ICMP Info
    elif packet.haslayer(ICMP):
        print("protocol: ICMP")
   # DNS Info
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
       print("DNS query",packet[DNSQR].qname.decode())
       print("packet length:",len(packet))
sniff(prn=packet_callback, store=False,count=20)
