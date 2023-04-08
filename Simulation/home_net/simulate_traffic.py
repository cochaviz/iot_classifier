from scapy.all import *
import time

# def pad_packet(packet):
#     #implement modes
#     #using basic round to next multiple of 100


def get_MAC():
    pkt = Ether(dst='ff:ff:ff:ff:ff')/ARP(pdst='192.168.124.30')
    ans = srp(pkt, verbose=0)
    # print(ans[0][0][1].hwsrc)
    return ans[0][0][1].hwsrc


def show_pack(packet):
    global pkt_curr_time
    sleep_time  = packet.time - pkt_curr_time
    pkt_curr_time = packet.time
    print(f"sleeping for {sleep_time}")
    time.sleep(float(sleep_time))

    if packet.haslayer('IP'):
        pack = Ether(src=packet['Ether'].src, dst = recv_MAC)
        newpack = pack / IP()
        newpack['IP'].dst = "192.168.124.30"
        newpack['IP'].src = packet['IP'].src

        newpack /= packet.getlayer(2)

        sendp(newpack, verbose=0, iface='eth0')

def peel_packet(packet):
    layer = 3
    finpacket = packet.getlayer(2)
    while True:
        if packet.getlayer(layer) is None:
            break
        finpacket /= packet.getlayer(layer)
        layer += 1
    # finpacket.show()

def set_arrival_time(packet):
    global pkt_curr_time
    # print()
    pkt_curr_time = packet.time

if __name__ == "__main__":
    file_name = "test1.pcap"
    recv_MAC = get_MAC()
    my_MAC = Ether().src
    pkt_curr_time = 86401
    sniff(offline=file_name,count=1, prn=set_arrival_time)
    # print(pkt_curr_time)
    sniff(offline=file_name,count=5000, prn=show_pack)
    # send(IP(dst='192.168.124.20') / ICMP())
