#! /usr/bin/env python3
import argparse
from collections import defaultdict
from math import log
from scapy.all import *


# Creo que lo mas facil es sniffear con Wireshark y una vez que tengamos todos los paquetes que queremos
# guardamos esa info en un archivo .pcap (packet capture) y lo laburamos con este script


BROADCAST_PHYSICAL_ADDRESS = 'ff:ff:ff:ff:ff:ff'


if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Sniff network packets.')
	
	parser.add_argument('-f', dest='pcap_file', default=None, help='used .pcap capture file')
	parser.add_argument('-c', dest='sniff_count', default=0, type=int, help='limit number of packets to sniff')
	parser.add_argument('-o', dest='output_files_prefix', default=None, 
						help='output all information using OUTPUT_FILES_PREFIX as filename prefix')

	args = parser.parse_args()

	sniffed_packets = sniff(count=args.sniff_count, offline=args.pcap_file, store=1)

	# una vez que tenemos la lista de paquetes
	# iria el codigo necesario para modelar las fuentes

	packets_total = len(sniffed_packets)
	broadcast_packets = 0

	# defaultdic() es para que si le pido una key que no existe, la defina y ponga el valor por defecto (0 en este caso)
	packets_dict = {
                'broadcast': defaultdict(lambda: 0), 
                'unicast': defaultdict(lambda: 0)
                }

	for packet in sniffed_packets:
		key = ''
		if(Ether in packet and 
			packet[Ether].dst == BROADCAST_PHYSICAL_ADDRESS):
			key = 'broadcast'
			broadcast_packets += 1
		else:
			key = 'unicast'
	
		# Agarro el nombre de la segunda capa simplemente porque vi a mano que esta era la que necesitamos
		protocol_layer_name = packet.getlayer(1).name
		packets_dict[key][protocol_layer_name] += 1

	print('Fuente S1 \n--------')

	print('broadcast:', dict(packets_dict['broadcast']))
	print('unicast:', dict(packets_dict['unicast']))


	# Armo la tabla y calculo la entropia

	tabla_resultado = {}
	S1_entropy = 0
	S1_maxentropy = log(packets_total, 2)

	for dest in packets_dict.keys():
		for prot in packets_dict[dest].keys():
			tabla_resultado[(dest, prot)] = {}
			tabla_resultado[(dest, prot)]['prob'] = packets_dict[dest][prot] * 1.0 / packets_total
			tabla_resultado[(dest, prot)]['info'] = -log(tabla_resultado[(dest, prot)]['prob'], 2)

			S1_entropy += tabla_resultado[(dest, prot)]['prob'] * tabla_resultado[(dest, prot)]['info']

	print(tabla_resultado)
 

 	# Sistemita pedorro para guardar los csv, nada fancy
	if args.output_files_prefix != None:
		file_tabla = open(args.output_files_prefix + '_tabla.csv', 'w')

		file_tabla.write('Destino,Protocolo,Probabilidad,Informacion\n')
		for (d,p) in tabla_resultado.keys():
			file_tabla.write(d + ',' + p + ',' + 
							str(tabla_resultado[(d,p)]['prob']) + ',' +
							str(tabla_resultado[(d,p)]['info']) + '\n')
		file_tabla.close()

		file_entropia = open(args.output_files_prefix + '_entropia.csv', 'w')
		file_entropia.write('Entropia,Entropia Maxima\n')
		file_entropia.write(str(S1_entropy) + ',' + str(S1_maxentropy))

		file_entropia.close()


	# p_broadcast = broadcast_packets * 1.0 / packets_total
	# p_unicast = 1 - p_broadcast
	# i_broadcast = -log(p_broadcast, 2)
	# i_unicast = -log(p_unicast, 2)
	# s1_entropy = p_broadcast*i_broadcast + p_unicast*i_unicast

	# print('\n--------')

	# print('P(broadcast) =', str(p_broadcast))
	# print('P(unicast) =', str(p_unicast))
	# print('I(broadcast) =', str(i_broadcast), 'bits')
	# print('I(broadcast) =', str(i_unicast), 'bits')
	# print('H(S1) =', str(s1_entropy), 'bits')
	# print('max H(S1) =', str(s1_maxentropy), 'bits')

	
