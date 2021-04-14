# Packet sniffer in python
# For Linux

import socket
import sys
from struct import *

import requests
import json
import time
from threading import Thread

# create an INET, raw socket


def getPackets():
	global data_ip
	data_ip = {}
	# receive a packet
	while True:
		packet = s.recvfrom(65565)
		# packet string from tuple
		packet = packet[0]

		# take first 20 characters for the ip header
		ip_header = packet[0:20]
		# now unpack them :)
		iph = unpack('!BBHHHBBH4s4s', ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]).strip()
		d_addr = socket.inet_ntoa(iph[9]).strip()

		# print_str = 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

		tcp_header = packet[iph_length:iph_length+20]

		# now unpack them :)
		tcph = unpack('!HHLLBBHHH', tcp_header)

		source_port = tcph[0]
		dest_port = tcph[1]
		sequence = tcph[2]
		acknowledgement = tcph[3]
		doff_reserved = tcph[4]
		tcph_length = doff_reserved >> 4

		print_str = 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
		# print(print_str)
		h_size = iph_length + tcph_length * 4
		data_size = len(packet) - h_size

		if(s_addr != our_ip):
			data_ip[s_addr] = data_ip.get(s_addr, 0) + data_size
		else:
			data_ip[d_addr] = data_ip.get(d_addr, 0) + data_size

# data_ip[our_ip] = data_ip.get(d_addr, 0) + data_size


def collect():
	global data_ip, domains, data_out
	data = data_ip.copy()
	# print(data)
	for k, v in data.items():
		if k not in domains:
			try:
				x = requests.get("https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_I6neX943tKNsqzugfEWuHSejCJ471&domainName={}&outputFormat=JSON".format(k))
				org = x.json()['WhoisRecord']['registryData']['registrant']['organization']
				domains[k] = org
				# print(org)
			except:
				pass

	for (k, v) in data.items():
		for (k2, v2) in domains.items():
			if(k == k2):
				data_out[v2] = v

	print(data_out)
	with open('data/data.json', 'w') as outfile:
		json.dump(data_out, outfile)
	with open('data/domain.json', 'w') as dnfile:
		json.dump(domains, dnfile)



if __name__ == "__main__":
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	our_ip = s.getsockname()[0].strip()
	s.close()
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	data_ip = dict()
	try:
		with open('data/domain.json') as dnfile:
			domains = json.load(dnfile)
	except:
		domains = dict()
	try:
		with open('data/data.json') as infile:
			data_out = json.load(infile)
	except:
		data_out = dict()

	Thread(target=getPackets).start()
	while True:
		collect()
		time.sleep(10)


# total = 0

# print(total, data_ip[our_ip])
