#! /usr/bin/env python3
import argparse
from scapy.all import *


# Creo que lo mas facil es sniffear con Wireshark y una vez que tengamos todos los paquetes que queremos
# guardamos esa info en un archivo .pcap (packet capture) y lo laburamos con este script


BROADCAST_PHYSICAL_ADDRESS = 'ff:ff:ff:ff:ff:ff'


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Sniff network packets.')
	
	parser.add_argument('-f', dest='pcap_file', default=None, help='used .pcap capture file')
	parser.add_argument('-c', dest='sniff_count', default=0, type=int, help='limit number of packets to sniff')

	args = parser.parse_args()

	sniffed_packets = sniff(count=args.sniff_count, offline=args.pcap_file, store=1)

	# una vez que tenemos la lista de paquetes
	# iria el codigo necesario para modelar las fuentes

	packets_broadcast = 0
	packets_total = len(sniffed_packets)

	for packet in sniffed_packets:
		if(Ether in packet and 
			packet[Ether].dst == BROADCAST_PHYSICAL_ADDRESS):
			packets_broadcast += 1

	print("Paquetes de broadcast: ", packets_broadcast)
	print("Paquetes totales: ", packets_total)
	print("Proporcion broadcast/totales: ", float(packets_broadcast)/float(packets_total))