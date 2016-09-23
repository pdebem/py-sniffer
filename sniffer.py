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
IP_TCP_CODE = "06"
IP_UDP_CODE = "11" #código 17

# Montagem de máscara, mais informações: https://docs.python.org/2/library/struct.html
ETH_UNPACK = '!6s6s2s'
ARP_UNPACK = '2s2s1s1s2s6s4s6s4s'
IPV4_UNPACK = '!1s1sH2s2s1s1s2s4s4s'

UDP_UNPACK = '!HH2s2s'
TCP_UNPACK = '!HHLL'

HTTP_UNPACK = '273s25s24s13s37s119s247s38s54s2s'

# Protocolos de aplicação
HTTP_PORT = 80
DNS_PORT = 53
HTTPS_PORT = 443
SSH_PORT = 22


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
         
        # Recebendo pacotes enquanto a thread estiver viva
        while not self.stop_event.is_set():
            packet = s.recvfrom(2048)
            packetLength = 14 # Tamanho inicial contando cabeçalho ethernet
            headers = packet[0] # Cabeçalho geral do pacote
            eth_header = struct.unpack(ETH_UNPACK, headers[0:14]) # Cabeçalho frame ethernet
            eth_type = binascii.hexlify(eth_header[2]) # tipo de frame ethernet

            if eth_type == ARP_CODE: # Verifica se o pacote é ARP
                packetLength = packetLength + 28
                arp_header = struct.unpack(ARP_UNPACK, headers[14:42])
                arp_type = binascii.hexlify(arp_header[4])
                self.metrics.addArpPacket(arp_type)

            elif eth_type == IPV4_CODE: # Verifica se o pacote é IP
                ip_header = struct.unpack(IPV4_UNPACK, headers[14:34])                
                packetLength = packetLength + 20 + ip_header[2] #incrementa cabecalho IP mais o total lenght
                self.metrics.addIp(socket.inet_ntoa(ip_header[9]))
                protocol = binascii.hexlify(ip_header[6])
                # Verifica dentro do pacote IP se é um ICMP
                if protocol == IP_ICMP_CODE:
                    icmp_type = binascii.hexlify(headers[34])
                    self.metrics.addIcmpPacket(icmp_type)

                elif protocol == IP_TCP_CODE: #TCP
                    tcp_header = struct.unpack(TCP_UNPACK, headers[34:46])
                    self.metrics.addTcpPort(tcp_header[1])

                    if tcp_header[1] == HTTP_PORT:
                        self.metrics.addHttpPacket()

                    if tcp_header[1] == HTTPS_PORT:
                        self.metrics.addHttpsPacket()

                    if tcp_header[1] == SSH_PORT:
                        self.metrics.addSSHPacket()

                elif protocol == IP_UDP_CODE: #UDP
                    udp_header = struct.unpack(UDP_UNPACK, headers[34:42])
                    udp_dest_port = udp_header[1]
                    udp_src_port = udp_header[0]
                    self.metrics.addUdpPort(udp_dest_port)

                    if udp_src_port == DNS_PORT or udp_dest_port == DNS_PORT:
                        self.metrics.addDnsPacket()

            self.metrics.addPacketLength(packetLength)


    # Encerra a execução da thread de sniffer
    def exit(self):
        try:
            #Imprime as estatísticas
            self.metrics.printGeneralInfo()
            self.metrics.printDataLink()
            self.metrics.printNetwork()
            self.metrics.printTransport()
            self.metrics.printApplication()
        finally:
            self.stop_event.set()


