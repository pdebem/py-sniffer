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

	#Coleta um pacote ARP
	def addArpPacket(self, opCode):
		if opCode == ARP_REQUEST_OP:
			self.arp_request = self.arp_request + 1
		elif opCode == ARP_REPLY_OP:
			self.arp_reply = self.arp_reply + 1
		else:
			print("Invalid arp op code: {}".format(opCode))


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
			

	# Print das métricas da camada de enlace
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


	