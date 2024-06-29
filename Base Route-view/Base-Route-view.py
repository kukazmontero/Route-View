import sys
import argparse
import json
from scapy.all import *
from scapy.layers.inet import ICMP, UDP, IP, TCP

# Configuración de argumentos
parser = argparse.ArgumentParser(description="Script para replicar el algoritmo MDA de Scamper usando Scapy")
parser.add_argument("-t", "--target", required=True, help="Objetivo a trazar (IP o dominio)")
parser.add_argument("-o", "--output", help="Archivo de salida en formato JSON")
args = parser.parse_args()

# Configuración de valores
CONFIDENCE_LEVEL = 99
MAX_PROBES = 10
TTL_START = 1
MAX_HOPS = 30

def send_probe(target, ttl, protocol):
    if protocol == "udp":
        packet = IP(dst=target, ttl=ttl) / UDP(dport=33434)
    elif protocol == "icmp":
        packet = IP(dst=target, ttl=ttl) / ICMP()
    elif protocol == "tcp":
        packet = IP(dst=target, ttl=ttl) / TCP(dport=80, flags="S")
    else:
        raise ValueError("Protocolo no soportado")
    
    reply = sr1(packet, verbose=0, timeout=1)
    return reply

def trace_mda(target, protocol):
    ttl = TTL_START
    routes = []
    connections = {}

    while ttl <= MAX_HOPS:
        hops = set()
        found_destination = False
        
        for _ in range(MAX_PROBES):
            reply = send_probe(target, ttl, protocol)
            if reply is not None:
                if reply.haslayer(ICMP):
                    if reply.type == 0:  # ICMP Echo Reply
                        routes.append({"ttl": ttl, "hops": [reply.src]})
                        if ttl > 1:
                            connections.setdefault(routes[-2]["hops"][0], []).append(reply.src)
                        print(f"Llegado al destino con ICMP: {reply.src}")
                        found_destination = True
                        break
                    elif reply.type == 11:  # ICMP Time Exceeded
                        hops.add(reply.src)
                elif reply.haslayer(UDP):
                    if reply.haslayer(ICMP) and reply[ICMP].type == 3 and reply[ICMP].code in [1, 2, 3, 9, 10, 13]:
                        routes.append({"ttl": ttl, "hops": [reply.src]})
                        if ttl > 1:
                            connections.setdefault(routes[-2]["hops"][0], []).append(reply.src)
                        print(f"Llegado al destino con UDP: {reply.src}")
                        found_destination = True
                        break
                    else:
                        hops.add(reply.src)
                elif reply.haslayer(TCP):
                    if reply[TCP].flags == 0x12:  # TCP SYN-ACK
                        routes.append({"ttl": ttl, "hops": [reply.src]})
                        if ttl > 1:
                            connections.setdefault(routes[-2]["hops"][0], []).append(reply.src)
                        print(f"Llegado al destino con TCP: {reply.src}")
                        found_destination = True
                        break
                    else:
                        hops.add(reply.src)
        
        if found_destination:
            if not hops:  # Si se llega al destino y no hay más hops
                routes.append({"ttl": ttl, "hops": []})
            break
        
        if not hops:
            routes.append({"ttl": ttl, "hops": []})
        else:
            routes.append({"ttl": ttl, "hops": list(hops)})
            if ttl > 1 and routes[-2]["hops"]:
                for previous_hop in routes[-2]["hops"]:
                    connections.setdefault(previous_hop, []).extend(list(hops))
        
        print(f"TTL {ttl} alcanzado en {list(hops)} con {protocol}")
        ttl += 1
    
    while ttl <= MAX_HOPS:
        routes.append({"ttl": ttl, "hops": []})
        ttl += 1
    
    return {"routes": routes, "connections": connections}

if __name__ == "__main__":
    try:
        protocols = ["icmp", "udp", "tcp"]
        results = {}
        
        for protocol in protocols:
            results[protocol] = trace_mda(args.target, protocol)
        
        if results:
            max_info_protocol = max(results, key=lambda x: len(results[x]["routes"]))
            final_result = results[max_info_protocol]
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(final_result, f, indent=4)
                print(f"Resultados guardados en {args.output}, usando el protocolo {max_info_protocol.upper()}")
            else:
                print(json.dumps(final_result, indent=4))
                print(f"Resultados obtenidos usando el protocolo {max_info_protocol.upper()}")
        
    except Exception as e:
        print(f"Error: {e}")
