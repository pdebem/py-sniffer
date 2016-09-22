#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket, sys, struct, binascii
from metrics import Metrics
from threading import Thread, Event
 
# Ethernet types
ARP_CODE = "0806"
IPV4_CODE = "0800"
IPV6_CODE = "86dd"

#IP Protocol Types
IP_ICMP_CODE = "01"

# Montagem de máscara https://docs.python.org/2/library/struct.html
ETH_UNPACK = '!6s6s2s'
ARP_UNPACK = '2s2s1s1s2s6s4s6s4s'
IPV4_UNPACK = '1s1s2s2s2s1s1s2s4s4s'


TCP_UNPACK = '!HHLLBBHHH'


class Sniffer(Thread):

    def __init__(self, interface):
        Thread.__init__(self)
        self.stop_event = Event()
        self.interface = interface
        self.metrics = Metrics()

    def run(self):
        try:
            s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            s.bind((self.interface, 0))
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
         
        # Recebendo pacotes
        while not self.stop_event.is_set():
            packet = s.recvfrom(2048)
            headers = packet[0] # Cabeçalho geral do pacote
            eth_header = struct.unpack(ETH_UNPACK, headers[0:14]) # Cabeçalho frame ethernet
            eth_type = binascii.hexlify(eth_header[2]) # tipo de frame ethernet

            if eth_type == ARP_CODE: # Verifica se o pacote é ARP
                arp_header = struct.unpack(ARP_UNPACK, headers[14:42])
                arp_type = binascii.hexlify(arp_header[4])
                self.metrics.addArpPacket(arp_type)

            elif eth_type == IPV4_CODE: # Verifica se o pacote é IP
                ip_header = struct.unpack(IPV4_UNPACK, headers[14:34])
                self.metrics.addIp(socket.inet_ntoa(ip_header[9]))
                protocol = binascii.hexlify(ip_header[6])
                # Verifica dentro do pacote IP se é um ICMP
                if protocol == IP_ICMP_CODE: 
                    icmp_type = binascii.hexlify(headers[34])
                    self.metrics.addIcmpPacket(icmp_type)
                #elif protocol == IP_TCP_CODE: #TCP

    def exit(self):
        self.metrics.printDataLink()
        self.metrics.printNetwork()
        self.stop_event.set()


