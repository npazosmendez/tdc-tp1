# coding: utf-8
import argparse
from math import log
from scapy.all import *
from collections import Counter
import numpy as np
import pickle

# -------------------------------------------------------------------------- #
# Modelado de fuente S1 #
" Recordar que tiene la forma `< unicast/broadcast , protocol > "
BROADCAST_PHYSICAL_ADDRESS = 'ff:ff:ff:ff:ff:ff'
def create_S1_source(packets):
    S1 = Counter() # Es un dict<*,int>
    for packet in packets:
        key = ''
        if(Ether in packet and
            packet[Ether].dst == BROADCAST_PHYSICAL_ADDRESS):
            key = 'broadcast'
        else:
            key = 'unicast'
        # Agarro el nombre de la segunda capa simplemente porque vi a mano que esta era la que necesitamos
        protocol_layer_name = packet.getlayer(1).name
        symbol = key + '\n' + protocol_layer_name
        S1[symbol]+=1
    return S1

# -------------------------------------------------------------------------- #
# Modelado de fuente S2 #
#### (solo paqs ARP) ####
"""
Para experimentar más fácil, los atributos ARP que determinan un símbolo de la
fuente S2 están parametrizados. Un paquete ARP tiene los siguientes campos:

    hwtype     : XShortField            = (1)
    ptype      : XShortEnumField        = (2048)
    hwlen      : ByteField              = (6)
    plen       : ByteField              = (4)
    op         : ShortEnumField         = (1)
    hwsrc      : ARPSourceMACField      = (None)
    psrc       : SourceIPField          = (None)
    hwdst      : MACField               = ('00:00:00:00:00:00')
    pdst       : IPField                = ('0.0.0.0')

La idea es que una función tome los paquetes sniffeados y una lista de
atributos ARP y devuelva la fuente. Por ejemplo:

    S2 = create_ARP_source(packets, ['op','psrc'])`

Eso crea una fuente S2 cuyos símbolos son `< who-has/is-at , src >`
(preguntar a Nico Pazos si algo no se entiende y está feo)
"""
# Funciones para crear la fuente

def format_symbol(symbol, attrs):
    """
    Toma una símbolo con atributos ARP 'attrs' y devuelve un bello string
    que puede leerse. Por ejemplo:
        format_symbol((1, 192.0.0.1) , ['op','psrc]) ---> 'who-has \n src: 192.0.0.1'
    """
    formatted_symbol = ''
    for i in range(len(attrs)):
        att = attrs[i]
        if att == 'op':
            formatted_symbol += 'is-at' if att == ARP.is_at else 'who-has'
        elif att == 'psrc':
            formatted_symbol += 'src: ' + str(symbol[i])
        elif att == 'pdst':
            formatted_symbol += 'dst: ' + str(symbol[i])
        # TODO: agregar formateo de más atributos si es necesario
        if not(i == len(attrs) - 1):
            formatted_symbol += '\n'
    return formatted_symbol

def create_ARP_source(packets, attrs):
    """
    Aplica el modelo de fuente ARP dado por 'attrs' a 'packets'.
    'attrs' es una lista de campos ARP. Por ejemplo:
        attrs = ['op','psrc']
    """
    S = Counter() # Es un dict<*,int>
    for packet in packets[ARP]:
        symbol = []
        for att in attrs:
            symbol.append(getattr(packet,att))
        S[format_symbol(symbol,attrs)]+=1
    return S

# -------------------------------------------------------------------------- #
## Análisis de fuentes ##
" Supone la fuente expresada como `dicc <simbolo, frecuencia> "

# Cálculo de información y entropía

def informacion_por_simbolo(source):
    "Devuelve dict<simbolo, info>"
    informacion = {}
    packets_total = sum(source.values())
    for symbol in source:
        proba = source[symbol] * 1.0 / packets_total
        informacion[symbol] = -log(proba, 2)
    return informacion

def proba_por_simbolo(source):
    "Devuelve dict<simbolo, probabilidad>"
    probas = {}
    packets_total = sum(source.values())
    for symbol in source:
        probas[symbol] = source[symbol] * 1.0 / packets_total
    return probas

def entropy(source):
    "Devuelve entropía de 'source' (float)"
    infos = informacion_por_simbolo(source)
    probas = proba_por_simbolo(source)
    # Esto funciona porque los símbolos en infos y probas están en el mismo orden
    info_vals = np.fromiter(infos.values(), dtype=np.float) 
    probs_vals = np.fromiter(probas.values(), dtype=np.float) 
    if info_vals.size != probs_vals.size:
        raise NameError("info_vals and probs_vals nor same length: %d - %d" % (len(info_vals), len(probs_vals)))
    return sum(info_vals*probs_vals)

def max_entropy(source):
    "Devuelve la máxima entropía que podría alcanzar 'source' (float)"
    return log(sum(source.values()), 2)

# Lectura / Escritura de fuente
def save_source(source, path):
    with open(path, 'wb') as f:
        pickle.dump(source, f, pickle.HIGHEST_PROTOCOL)

def load_source(path):
    with open(path, 'rb') as f:
        return pickle.load(f)
    
# -------------------------------------------------------------------------- #

# ARP message mapping
def getArpHeatmapDataframe(sniffedPackets):
    d = dict()
    for p in sniffedPackets[ARP]:
        if p.psrc not in d.keys():
            d[p.psrc] = dict()
        if p.pdst not in d[p.psrc].keys():
            d[p.psrc][p.pdst] = 0
        d[p.psrc][p.pdst] = d[p.psrc][p.pdst] + 1
    return d

# -------------------------------------------------------------------------- #

if __name__ == '__main__':

    # Seteo de argumentos
	parser = argparse.ArgumentParser(description='Sniff network packets.')

	parser.add_argument('-f', dest='pcap_file', default=None, help='used .pcap capture file')
	parser.add_argument('-c', dest='sniff_count', default=0, type=int, help='limit number of packets to sniff')
	parser.add_argument('-o', dest='output_files_prefix', default=None,
						help='output sources using pickle with OUTPUT_FILES_PREFIX as filename prefix')

	args = parser.parse_args()

    # Leo la data .pcap o sniffeo
	sniffed_packets = sniff(count=args.sniff_count, offline=args.pcap_file, store=1)

    # Calculo las fuentes
	S1 = create_S1_source(sniffed_packets)
	S2_attrs = ['op','psrc'] # podría ser argumento del script, pero quilombo
	S2 = create_ARP_source(sniffed_packets, S2_attrs)
	heatmapDataFrame = getArpHeatmapDataframe(sniffed_packets)    
        
	# Guardo las fuentes
	if args.output_files_prefix != None:
		save_source(S1, args.output_files_prefix + '_S1.pkl')
		save_source(S2, args.output_files_prefix + '_S2.pkl')
		save_source(heatmapDataFrame, args.output_files_prefix + '_hmap.pkl')
