import sys
import argparse
import json
import time
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
INTERVAL = 300  # Intervalo de 300 segundos entre modalidades

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
    destination_reached = False

    while ttl <= MAX_HOPS:
        hops = set()
        for _ in range(MAX_PROBES):
            reply = send_probe(target, ttl, protocol)
            if reply is not None:
                if reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 0:  # ICMP Echo Reply
                    routes.append({"ttl": ttl, "hops": [reply.src]})
                    if ttl > 1 and len(routes) > 1 and routes[-2]["hops"]:
                        connections.setdefault(routes[-2]["hops"][0], []).append(reply.src)
                    destination_reached = True
                    print(f"Llegado al destino: {reply.src}")
                    break
                elif reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 11:  # ICMP Time Exceeded
                    hops.add(reply.src)
        
        if destination_reached:
            break

        routes.append({"ttl": ttl, "hops": list(hops)})
        if ttl > 1 and len(routes) > 1 and routes[-2]["hops"]:
            for previous_hop in routes[-2]["hops"]:
                connections.setdefault(previous_hop, []).extend(list(hops))

        print(f"TTL {ttl} alcanzado en {list(hops)}")
        ttl += 1

    return routes, connections

def run_all_protocols(target):
    results = {}
    protocols = ["icmp", "udp", "tcp"]

    for i, protocol in enumerate(protocols):
        if i > 0:
            print(f"Esperando {INTERVAL} segundos antes de ejecutar el siguiente protocolo...")
            time.sleep(INTERVAL)
        print(f"Ejecutando protocolo: {protocol}")
        routes, connections = trace_mda(target, protocol)
        total_hops = len(routes)
        total_ips = len(set(hop for route in routes for hop in route["hops"] if hop != target))
        # Excluir la IP del destino final para el cálculo de total_ips
        # if total_hops > 0 and routes[-1]["hops"] == [target]:
        #     total_hops -= 1  # Excluir el salto al destino final
        results[protocol] = {
            "routes": routes,
            "connections": connections,
            "total_ips": total_ips,
            "total_hops": total_hops,
            "efficiency": total_ips / total_hops if total_hops > 0 else 0
        }
        print(f"Protocolo: {protocol}, Total IPs: {total_ips}, Total Hops: {total_hops}, Eficiencia: {results[protocol]['efficiency']}")
    
    # Seleccionar el protocolo con la mejor eficiencia (total_ips / total_hops)
    best_protocol = max(results.keys(), key=lambda p: results[p]["efficiency"])
    best_result = results[best_protocol]

    return best_protocol, best_result

if __name__ == "__main__":
    try:
        best_protocol, best_result = run_all_protocols(args.target)
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(best_result, f, indent=4)
            print(f"Resultados guardados en {args.output}")
        else:
            print(json.dumps(best_result, indent=4))
        print(f"El mejor protocolo fue: {best_protocol}")
    except Exception as e:
        print(f"Error: {e}")
