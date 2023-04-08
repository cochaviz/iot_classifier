from scapy.all import *
import random 

# level = 100

def determine_padding(length, level) -> int:
    if level == 100:
        print("100")
        if length < 100:
            return (100 - length)
        elif length < 200:
            return (200 - length)
        elif length < 300:
            return (300 - length)
        else:
            # print(random.randint(300, 999))
            return (random.randint(0, 999 - length))
    elif level == 500:
        if length < 500:
            return (500 - length)
        else:
            return(random.randint(0, 999 - length))
    elif level == 700:
        if length < 700:
            return (700 - length)
        else:
            return(random.randint(0, 999 - length))
    elif level == 900:
        # print("900")
        if length < 900:
            return (900 - length)
        else:
            return(random.randint(0, 1000 - length))
    else:
        if length < 1400:
            return(random.randint(0, 1400 - length))
        elif length < 1500:
            return(1500 - length) 
    



def padding(packet):
    if packet.haslayer('IP'):
        # packet['Ether'].dst = "02:42:c0:a8:7c:1e"
        # packet['Ether'].src = "02:42:c0:a8:7c:14"
        # packet['IP'].dst = "192.168.124.30"
        # packet['IP'].src = "192.168.124.20"
        pack = Ether(src=packet['Ether'].src, dst="02:42:c0:a8:7c:1e")
        newpack = pack / IP()
        newpack['IP'].dst = "192.168.124.30"
        newpack['IP'].src = "192.168.124.20"
        newpack /= packet.getlayer(2)
        padding = Padding()
        pad_amt = determine_padding(len(newpack), 900)
        print(f"pack length: {len(newpack)}, pad length: {pad_amt}")
        
        padding = "\x00" * pad_amt

        padpack = newpack / padding
        print(len(padpack))
        # padpack.show()
        sendp(newpack, verbose=0)

if __name__ == "__main__":
    sniff(prn=padding, count=50)