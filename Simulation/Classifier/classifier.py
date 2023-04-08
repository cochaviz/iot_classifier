from scapy.all import *
import time
import signal
from threading import Thread
from multiprocessing import Process
import numpy as np
import pickle
from sklearn import neighbors, model_selection, metrics



def classifier(pkts):
    model = pickle.load(open('Knn.pickle', 'rb'))
    pkt_len = []
    for i in pkts:
        pkt_len.append(len(i))
    print(pkts)
    if len(pkt_len) > 0:
        print(pkt_len)
        mean = np.mean(pkt_len)
        stdev = np.std(pkt_len)
        packets = len(pkts)
        print(f"mean: {mean}, stdev: {stdev}, number of packets: {packets}")
        tingg = model.predict(np.array([mean, stdev, packets]).reshape(1, -1))
        print(f"the prediction is: {tingg}")

    #figure out classifier and do it here

# figure out filtering and implement here
# create a dict with an array for each mac address
def classifier_with_filtering(pkts):
    mac_pkt_len = {}
    if len(pkts) > 0:
        for i in pkts:
            if i['Ether'].src not in mac_pkt_len:
                mac_pkt_len[i['Ether'].src] = []
                mac_pkt_len[i['Ether'].src].append(len(i))
            else:
                mac_pkt_len[i['Ether'].src].append(len(i))
        print(mac_pkt_len)
    for i in mac_pkt_len:
        print(f"{i}: mean: {np.mean(mac_pkt_len[i])}, stdev: {np.std(mac_pkt_len[i])}, number of packets: {len(mac_pkt_len[i])}")
    # model = pickle.load('nneighbours', 'rb')
    #figure out classifier and implement here as well

def one_sec_capture():  
    try:
        while True:
            pkts = sniff(timeout=1)
            print("Starting stats")
            tsk = Process(target=classifier, args=(pkts,))
            tsk.start()
            print("Done with stats")
    except KeyboardInterrupt:
        pass



if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))
    one_sec_capture()