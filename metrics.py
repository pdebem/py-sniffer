#!/usr/bin/env python
# -*- coding: utf-8 -*-
from collections import Counter

#ARP types
ARP_REQUEST_OP="0001"
ARP_REPLY_OP="0002"

#ICMP types
ICMP_REQUEST = "08"
ICMP_REPLY = "00"

# Classe que computa as métricas pedidas no trabalho
class Metrics:

    def __init__(self):
        self.arp_request = 0
        self.arp_reply = 0
        self.icmp_request = 0
        self.icmp_reply = 0
        self.icmp = 0
        self.ips = []
        self.tcp = 0
        self.openTcp = 0
        self.tcpPorts = []
        self.udp = 0
        self.udpPorts = []
        self.sites = []
        self.dns = 0
        self.http = 0
        self.https = 0
        self.ssh = 0
        self.packetSizes = [] #tamanho dos pacotes trafegados


    # Registra tcp aberto
    def addTcpConnection(self):
        self.openTcp = self.openTcp + 1


    # Adiciona pacote SSH - Aplicaçao
    def addSSHPacket(self):
        self.ssh = self.ssh + 1


    # Imprime informações gerais
    def printGeneralInfo(self):
        if len(self.packetSizes) == 0:
            greater = 0
            smaller = 0
            mean = 0
        else:
            greater = max(self.packetSizes)
            smaller = min(self.packetSizes)
            mean = sum(self.packetSizes) / len(self.packetSizes)

        print("================================")
        print("-------- TRANSPORTE ------------")
        print("================================")
        print("Maior pacote trafegado: {}".format(greater))
        print("Menor pacote trafegado: {}".format(smaller))
        print("Media de tamanho trafegado: {}".format(mean))

    # Registra o tamanho dos pacotes
    def addPacketLength(self, length):
        self.packetSizes.append(length)


    #Coleta um pacote ARP
    def addArpPacket(self, opCode):
        if opCode == ARP_REQUEST_OP:
            self.arp_request = self.arp_request + 1
        elif opCode == ARP_REPLY_OP:
            self.arp_reply = self.arp_reply + 1
        else:
            print("Invalid arp op code: {}".format(opCode))


    # Adiciona a url de um site
    def addSite(self, site):
        self.sites.append(site)


    # Registra um tráfego de pacote DNS
    def addDnsPacket(self):
        self.dns = self.dns + 1


    #Registra a chegada de um pacote HTTP
    def addHttpPacket(self):
        self.http = self.http+1

    #Registra a chegada de um pacote HTTPS (Secure)
    def addHttpsPacket(self):
        self.https = self.https+1


    #Coleta pacotes ICMP
    def addIcmpPacket(self, type):
        self.icmp = self.icmp + 1
        if type == ICMP_REQUEST:
            self.icmp_request = self.icmp_request + 1
        elif type == ICMP_REPLY:
            self.icmp_reply = self.icmp_reply + 1


    # Adiciona um ip a base de informações
    def addIp(self, ip):
        self.ips.append(ip)


    # Registra um pacote TCP e sua porta de destino
    def addTcpPort(self, port):
        self.tcp = self.tcp + 1
        self.tcpPorts.append(port)


    # Registra um pacote UDP e sua porta de destino
    def addUdpPort(self, port):
        self.udp = self.udp + 1
        self.udpPorts.append(port)


    # Imprime informações da camada de rede (datagrama IP)
    def printNetwork(self):
        #Calculando os 5 IPs mais acessados, ou seja, com mais ocorrência na lista
        mostCommonIps = Counter(self.ips).most_common()[0:5]

        #Calculando a porcentagem de icmp request e reply em relação ao total
        if self.icmp == 0:
            percentRequest = 0
            percentReply = 0
        else:
            percentRequest = (float(self.icmp_request) / float(self.icmp))*100
            percentReply = (float(self.icmp_reply) / float(self.icmp))*100

        print("================================")
        print("------------ REDE --------------")
        print("================================")
        print("Qtd total de pacotes ICMP: {}".format(self.icmp))
        print("Qtd ICMP Echo Request: {} - {}%".format(self.icmp_request, percentRequest))
        print("Qtd ICMP Echo Reply: {} - {}%".format(self.icmp_reply, percentReply))        
        print("5 IPs mais acessados:")
        for ip_record in mostCommonIps:
            print(" - {} - {} acessos".format(ip_record[0],ip_record[1]))
            

    # Print das métricas da camada de ENLACE
    def printDataLink(self):
        #Calculo de porcentagens de ARP
        arp_total = self.arp_request + self.arp_reply
        if arp_total != 0:
            percentRequest = (float(self.arp_request) / float(arp_total))*100
            percentReply = (float(self.arp_reply) / float(arp_total))*100
        else:
            percentReply = 0
            percentRequest = 0

        print("================================")
        print("---------- ENLACE --------------")
        print("================================")
        print("Qtd Arp Request: {} - {}%".format(self.arp_request, percentRequest))
        print("Qtd Arp Reply: {} - {}%".format(self.arp_reply,percentReply))


    # Imprime as métricas relacionadas a camada de TRANSPORTE
    def printTransport(self):
        mostCommonTcpPorts = Counter(self.tcpPorts).most_common()[0:5]
        mostCommonUdpPorts = Counter(self.udpPorts).most_common()[0:5]
        total = self.tcp + self.udp
        if total == 0:
            percentTcp = 0
            percentUdp = 0
        else:
            percentTcp = (float(self.tcp) / float(total))*100
            percentUdp = (float(self.udp) / float(total))*100

        print("================================")
        print("-------- TRANSPORTE ------------")
        print("================================")
        print("Qtd TCP: {} - {}%".format(self.tcp, percentTcp))
        print("Conexões TCPs abertas: {}".format(self.openTcp))
        print("Qtd UDP: {} - {}%".format(self.udp, percentUdp))
        print("5 Portas TCPs mais acessadas:")
        for tcp_record in mostCommonTcpPorts:
            print(" - {} - {} acessos".format(tcp_record[0],tcp_record[1]))

        print("5 Portas UDPs mais acessadas:")
        for udp_record in mostCommonUdpPorts:
            print(" - {} - {} acessos".format(udp_record[0],udp_record[1]))


    # Imprime métricas da camada de APLICAÇÃO
    def printApplication(self):
        mostCommonSites = Counter(self.sites).most_common()[0:5]
        appTotal = self.http + self.dns + self.https + self.ssh
        if appTotal == 0:
            percentHttp = 0
            percentHttps = 0
            percentDns = 0
            percentSSH = 0
        else:
            percentHttp = (float(self.http) / float(appTotal))*100
            percentHttps = (float(self.https) / float(appTotal))*100
            percentDns = (float(self.dns) / float(appTotal))*100
            percentSSH = (float(self.ssh) / float(appTotal))*100

        print("================================")
        print("--------- APLICAÇÃO ------------")
        print("================================")
        print("Qtd HTTP:  {} - {}%".format(self.http, percentHttp))
        print("Qtd HTTPS: {} - {}%".format(self.https, percentHttps))
        print("Qtd DNS: {} - {}%".format(self.dns, percentDns))
        print("Qtd SSH: {} - {}%".format(self.ssh, percentSSH))
        #print("5 Sites mais acessados:")
        #for site_record in mostCommonSites:
        #    print(" - {} - {} acessos".format(site_record[0],site_record[1]))