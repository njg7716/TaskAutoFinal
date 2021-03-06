#!/usr/bin/python
from scapy.all import *

#1 bit is equal to .125 bytes
def main():
    packets = rdpcap('Node1.pcap')
    requestsrecv = 0
    replysrecv = 0
    requestsent = 0
    replysent = 0
    replydatasent = 0
    replydatarecv = 0
    requestdatarecv = 0
    requestdatasent = 0
    for packet in packets:
        if packet.haslayer(ICMP):
            if str(packet[IP].src) == '192.168.200.1' and str(packet[ICMP].type) == '8':    #Echo requests recieved from this IP
                requestsrecv += 1
                requestdatarecv += len(packet[Raw].load) + 14
            if str(packet[IP].src) == '192.168.200.1' and str(packet[ICMP].type) == '0':    #Echo replies recieved from this IP
                replysrecv += 1
                replydatarecv += len(packet[Raw].load) + 14
            if str(packet[IP].dst) == '192.168.200.2' and str(packet[ICMP].type) == '8':    #Echo requests sent to this IP
                requestsent += 1
                requestdatasent += len(packet[Raw].load) + 14
            if str(packet[IP].dst) == '192.168.200.2' and str(packet[ICMP].type) == '0':    #Echo replies sent to this IP
                replysent += 1
                replydatasent  += len(packet[Raw].load) + 14
    print('Number of ICMP requests recieved from 192.168.200.1: ' + str(requestsrecv))
    print('Number of ICMP replies recieved from 192.168.200.1: ' + str(replysrecv))
    print('Number of ICMP requests sent to 192.168.200.1: ' + str(requestsent))
    print('Number of ICMP replies sent to 192.168.200.1: ' + str(replysent))
    print('Amount of ICMP request data recieved from 192.168.200.1: ' + str(requestdatarecv) + ' bits, ' + str(float(requestdatarecv)*.125) + ' bytes')
    print('Amount of ICMP reply data recieved from 192.168.200.1: ' + str(replydatarecv) + ' bits, ' + str(float(replydatarecv)*.125) + ' bytes')
    print('Amount of ICMP request data sent from 192.168.200.1: ' + str(requestdatasent) + ' bits, ' + str(float(requestdatasent)*.125) + ' bytes')
    print('Amount of ICMP reply data sent from 192.168.200.1: ' + str(replydatasent) + ' bits, ' + str(float(replydatasent)*.125) + ' bytes')

if __name__ == "__main__":
    main()