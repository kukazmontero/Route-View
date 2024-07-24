import os
import sys
import argparse
import json
import time
import requests
import socket
from scapy.all import *
from scapy.layers.inet import ICMP, UDP, IP, TCP
import nmap
import whois
import subprocess
from censys.search import CensysHosts
from dotenv import load_dotenv
from datetime import datetime
import math
import random
from pythonping import ping
from collections import defaultdict



# Cargar variables de entorno
# load_dotenv()

# Configuración de credenciales
# IPINFO_ACCESS_TOKEN = os.getenv('')

# Configuración de argumentos
parser = argparse.ArgumentParser(description="Script para replicar el algoritmo MDA de Scamper usando Scapy")
parser.add_argument("-t", "--target", required=True, help="Objetivo a trazar (IP o dominio)")
parser.add_argument("-o", "--output", help="Archivo de salida en formato JSON")

args = parser.parse_args()

# Configuración de valores
CONFIDENCE_LEVEL = 0.99
MAX_PROBES = 10
TTL_START = 1
MAX_HOPS = 30
TIMEOUT = 2
INTERVAL = 10  # Intervalo entre modalidades (ICMP, UDP y TCP)
PORT_RANGE_START = 33434
max_ttl = 30  # Máximo número de saltos
probes_per_ttl = 3  # Número de probes por cada TTL
CONSECUTIVE_FAILURE_THRESHOLD = 5  # Umbral de fallos consecutivos

def calculate_probes_needed(confidence, success_rate):
    if success_rate <= 0:
        return MAX_PROBES
    if success_rate >= 1:
        return 1
    return math.ceil(math.log(1 - confidence) / math.log(1 - success_rate))

def send_probe_icmp(target, ttl):
    try:
        packet = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=0, timeout=TIMEOUT)
        return reply
    except Exception as e:
        print(f"Error enviando probe: {e}")
        return None

def send_probe_udp(dst_ip, ttl, sport, dport):
    pkt = IP(dst=dst_ip, ttl=ttl) / UDP(sport=sport, dport=dport)
    reply = sr1(pkt, verbose=0, timeout=TIMEOUT)
    return reply

def send_probe_tcp(dst, ttl, dport):
    src_port = random.randint(1024, 65535)
    ip = IP(dst=dst, ttl=ttl)
    syn = TCP(sport=src_port, dport=dport, flags='S', seq=random.randint(1000, 10000))
    packet = ip/syn
    reply = sr1(packet, verbose=0, timeout=TIMEOUT)
    return reply

def trace_mda_icmp(target):
    ttl = TTL_START
    routes = []
    connections = {}
    destination_reached = False
    consecutive_failures = 0
    probes_sent = 0
    success_count = 0

    while ttl <= MAX_HOPS and not destination_reached:
        hops = set()
        ttl_probes_sent = 0
        ttl_success_count = 0

        while ttl_probes_sent < MAX_PROBES:
            reply = send_probe_icmp(target, ttl)
            ttl_probes_sent += 1
            probes_sent += 1

            if reply is not None:
                ttl_success_count += 1
                success_count += 1
                if reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 0:  # ICMP Echo Reply
                    routes.append({"ttl": ttl, "hops": [reply.src]})
                    if ttl > 1 and len(routes) > 1 and routes[-2]["hops"]:
                        connections.setdefault(routes[-2]["hops"][0], []).append(reply.src)
                    destination_reached = True
                    print(f"Llegado al destino: {reply.src}")
                    break
                elif reply.haslayer(ICMP) and reply.getlayer(ICMP).type == 11:  # ICMP Time Exceeded
                    hops.add(reply.src)

            success_rate = ttl_success_count / ttl_probes_sent
            probes_needed = calculate_probes_needed(CONFIDENCE_LEVEL, success_rate)
            if ttl_success_count >= probes_needed:
                break

        if destination_reached:
            break

        if not hops:
            consecutive_failures += 1
        else:
            consecutive_failures = 0

        if consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD:
            print(f"Deteniendo trazado: {CONSECUTIVE_FAILURE_THRESHOLD} TTLs consecutivos sin respuesta")
            break

        routes.append({"ttl": ttl, "hops": list(hops)})
        if ttl > 1 and len(routes) > 1 and routes[-2]["hops"]:
            for previous_hop in routes[-2]["hops"]:
                connections.setdefault(previous_hop, []).extend(list(hops))

        print(f"TTL {ttl} alcanzado en {list(hops)}")

        ttl += 1

    packet_loss = calculate_packet_loss(probes_sent, success_count)
    return routes, connections, packet_loss

def explore_paths(dest_ip, ttl, dport, max_probes):
    paths = {}
    for probe in range(max_probes):
        sport = random.randint(33434, 33534)
        reply = send_probe_udp(dest_ip, ttl, sport, dport)
        if reply:
            if reply.src not in paths:
                paths[reply.src] = 1
            else:
                paths[reply.src] += 1
    return paths

def trace_mda_udp(dest_ip):
    ttl = TTL_START
    routes = []
    connections = {}
    destination_reached = False
    consecutive_failures = 0
    probes_sent = 0
    success_count = 0

    while ttl <= max_ttl and not destination_reached:
        paths = explore_paths(dest_ip, ttl, PORT_RANGE_START, probes_per_ttl)
        hops = list(paths.keys())
        success_count += len(hops)
        probes_sent += probes_per_ttl

        if dest_ip in hops:
            destination_reached = True
            print(f"Llegado al destino: {dest_ip}")

        if not hops:
            consecutive_failures += 1
        else:
            consecutive_failures = 0

        if consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD:
            print(f"Deteniendo trazado: {CONSECUTIVE_FAILURE_THRESHOLD} TTLs consecutivos sin respuesta")
            break

        routes.append({"ttl": ttl, "hops": hops})
        if ttl > 1 and len(routes) > 1 and routes[-2]["hops"]:
            for previous_hop in routes[-2]["hops"]:
                connections.setdefault(previous_hop, []).extend(hops)

        print(f"TTL {ttl} alcanzado en {hops}")

        ttl += 1

    packet_loss = calculate_packet_loss(probes_sent, success_count)
    return routes, connections, packet_loss

def trace_mda_tcp(target_ip):
    ttl = TTL_START
    routes = []
    connections = {}
    destination_reached = False
    consecutive_failures = 0
    probes_sent = 0
    success_count = 0

    while ttl <= max_ttl and not destination_reached:
        hops = set()
        ttl_probes_sent = 0
        ttl_success_count = 0

        for _ in range(probes_per_ttl):
            reply = send_probe_tcp(target_ip, ttl, PORT_RANGE_START)
            ttl_probes_sent += 1
            probes_sent += 1

            if reply is not None:
                ttl_success_count += 1
                success_count += 1
                if reply.haslayer(ICMP):
                    icmp_type = reply.getlayer(ICMP).type
                    if icmp_type == 11:  # Time-to-live exceeded
                        hops.add(reply.src)
                    elif icmp_type == 3:  # Destination unreachable
                        hops.add(reply.src)
                        print(f"Destination unreachable from {reply.src}")
                        destination_reached = True
                        break
                elif reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:  # SYN-ACK received
                    hops.add(reply.src)
                    send_rst = IP(dst=target_ip)/TCP(dport=PORT_RANGE_START, sport=reply.sport, flags="R")
                    send(send_rst, verbose=0)
                    print(f"Reached destination: {reply.src}")
                    destination_reached = True
                    break

        hops = list(hops)
        if not hops:
            consecutive_failures += 1
        else:
            consecutive_failures = 0

        if consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD:
            print(f"Deteniendo trazado: {CONSECUTIVE_FAILURE_THRESHOLD} TTLs consecutivos sin respuesta")
            break

        routes.append({"ttl": ttl, "hops": hops})
        if ttl > 1 and len(routes) > 1 and routes[-2]["hops"]:
            for previous_hop in routes[-2]["hops"]:
                connections.setdefault(previous_hop, []).extend(hops)

        print(f"TTL {ttl} alcanzado en {hops}")

        ttl += 1

    packet_loss = calculate_packet_loss(probes_sent, success_count)
    return routes, connections, packet_loss

def calculate_packet_loss(probes_sent, success_count):
    if probes_sent == 0:
        return 0.0
    return ((probes_sent - success_count) / probes_sent) * 100

def run_all_protocols(target):
    results = {}
    protocols = ["udp","icmp", "tcp"]

    for i, protocol in enumerate(protocols):
        if i > 0:
            print(f"Esperando {INTERVAL} segundos antes de ejecutar el siguiente protocolo...")
            time.sleep(INTERVAL)
        print(f"Ejecutando protocolo: {protocol}")
        if protocol == "icmp":
            routes, connections, packet_loss = trace_mda_icmp(target)
        elif protocol == "udp":
            routes, connections, packet_loss = trace_mda_udp(target)
        elif protocol == "tcp":
            routes, connections, packet_loss = trace_mda_tcp(target)
        total_hops = len(routes)
        total_ips = sum(1 for route in routes if route["hops"])
        results[protocol] = {
            "routes": routes,
            "connections": connections,
            "total_ips": total_ips,
            "total_hops": total_hops,
            "efficiency": total_ips / total_hops if total_hops > 0 else 0,
            "packet_loss": packet_loss
        }
        print(f"Protocolo: {protocol}, Total IPs: {total_ips}, Total Hops: {total_hops}, Eficiencia: {results[protocol]['efficiency']}, Pérdida de Paquetes: {packet_loss}%")
    
    # Seleccionar el protocolo con la mejor eficiencia (total_ips / total_hops)
    best_protocol = max(results.keys(), key=lambda p: results[p]["efficiency"])
    best_result = results[best_protocol]

    return best_protocol, best_result, results

def get_geo_info(ip):
    url = f"https://ipinfo.io/{ip}/json?token=f6b8889a44e63b"
    try:
        response = requests.get(url)
        data = response.json()
        if "loc" in data:
            loc = data["loc"].split(',')
            return {"latitude": loc[0], "longitude": loc[1]}
        return {}
    except Exception as e:
        print(f"Error obteniendo datos geográficos para IP {ip}: {e}")
        return {}

def ping_ip(ip, count=10):
    try:
        response = ping(ip, count=count, verbose=True)
        return parse_ping_output(response)
    except Exception as e:
        print(f"Error ejecutando ping para IP {ip}: {e}")
        return {}

def parse_ping_output(response):
    latencies = [result.time_elapsed_ms for result in response if result.success]
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        jitter_max = max(latencies)
        jitter_min = min(latencies)
        return {"avg_latency": avg_latency, "jitter_max": jitter_max, "jitter_min": jitter_min}
    return {}

def get_censys_data(ip):
    try:
        time.sleep(1)
        h = CensysHosts(api_id="8cb5cdc8-6370-42a1-8892-f5a53832b075", api_secret="Vg2oMpKPrEu91s3kQlVyYM5GTxpdS5dA")
        host = h.view(ip)
        return host
    except Exception as e:
        print(f"Error obteniendo datos de Censys para IP {ip}: {e}")
        return {}

# Funciones para OSINT infraestructura
def get_nmap_data(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sV')
        return nm[ip]
    except nmap.PortScannerError as e:
        print(f"Error obteniendo datos de Nmap para IP {ip}: {e}")
        return {}
    except Exception as e:
        print(f"Error obteniendo datos de Nmap para IP {ip}: {e}")
        return {}

def get_whois_data(ip):
    try:
        return whois.whois(ip)
    except Exception as e:
        print(f"Error obteniendo datos de Whois para IP {ip}: {e}")
        return {}

def get_osint_data(ip_list):
    osint_results = {}
    geo_info = {}
    for ip in ip_list:
        try:
            print("Osint de ", ip)
            censys_data = get_censys_data(ip)
            nmap_data = get_nmap_data(ip)
            whois_data = get_whois_data(ip)
            geo_info[ip] = get_geo_info(ip)
            osint_results[ip] = {
                "censys": censys_data,
                "nmap": nmap_data,
                "whois": whois_data,
                "geo": geo_info[ip]
            }
        except Exception as e:
            print(f"Error obteniendo datos de IP {ip}: {e}")
    return osint_results

def calculate_all_routes_with_nulls(routes, connections):
    all_routes = []

    def dfs_with_nulls(current_route, ttl_index):
        if ttl_index >= len(routes):
            all_routes.append(current_route.copy())
            return

        current_hops = routes[ttl_index]["hops"]
        if not current_hops:
            current_route.append(None)
            dfs_with_nulls(current_route, ttl_index + 1)
            current_route.pop()
        else:
            for next_hop in current_hops:
                current_route.append(next_hop)
                dfs_with_nulls(current_route, ttl_index + 1)
                current_route.pop()

    for start_node in routes[0]["hops"]:
        dfs_with_nulls([start_node], 1)

    return all_routes


def normalize_value(value, min_value, max_value):
    if max_value - min_value == 0:
        return 0
    return (value - min_value) / (max_value - min_value)

def calculate_route_diversity(routes, connections, osint_results):
    if not routes:
        return 0

    all_possible_routes = calculate_all_routes_with_nulls(routes, connections)
    lev_distances = []
    for i in range(len(all_possible_routes)):
        for j in range(i + 1, len(all_possible_routes)):
            lev_distances.append(levenshtein_distance(all_possible_routes[i], all_possible_routes[j]))

    avg_lev_distance = sum(lev_distances) / len(lev_distances) if lev_distances else 0

    # Calcular max_hop_count considerando los nodos con información y excluyendo los nulos
    hop_counts_with_info = [len(route["hops"]) for route in routes if route["hops"]]
    max_hop_count_with_info = len(hop_counts_with_info)

    # Ajustar max_lev_distance excluyendo los nodos nulos
    max_hop_count = max(len(route) for route in all_possible_routes) if all_possible_routes else 0
    max_lev_distance = max_hop_count - 2 - sum(1 for route in all_possible_routes if None in route)

    load_balancing = len(all_possible_routes)

    device_types = set()
    for ip in osint_results:
        nmap_data = osint_results[ip].get("nmap", {})
        open_ports = nmap_data.get("tcp", {}).keys()
        device_type = identify_device(open_ports)
        if device_type:
            device_types.add(device_type)

    device_diversity = len(device_types)

    # Definición de los valores mínimos y máximos
    min_lev_distance = 0
    min_hop_count = 1
    max_device_diversity = 5
    min_device_diversity = 1

    # Normalización de cada métrica
    norm_lev_distance = normalize_value(avg_lev_distance, min_lev_distance, max_lev_distance)
    norm_hop_count = normalize_value(max_hop_count_with_info, min_hop_count, max_hop_count)
    norm_device_diversity = normalize_value(device_diversity, min_device_diversity, max_device_diversity)

    # Cálculo del índice de diversidad
    diversity_index = 0.5 * norm_lev_distance + 0.25 * norm_hop_count + 0.25 * norm_device_diversity

    print("Maximo salto: ", max_hop_count, " - max_lev_distance: ",max_lev_distance," - Normalizados lev: ", norm_lev_distance, " norm_hop_count ", norm_hop_count, " norm_device_diversity ", norm_device_diversity)

    return diversity_index

def levenshtein_distance(route1, route2):
    if len(route1) < len(route2):
        return levenshtein_distance(route2, route1)

    if len(route2) == 0:
        return len(route1)

    previous_row = list(range(len(route2) + 1))
    for i, c1 in enumerate(route1):
        current_row = [i + 1]
        for j, c2 in enumerate(route2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def identify_device(open_ports):
    if 22 in open_ports:
        return "SSH Server"
    elif 179 in open_ports:
        return "BGP Server"
    elif 53 in open_ports:
        return "DNS Server"
    elif 23 in open_ports:
        return "Telnet Server"
    else:
        return "Unknown"


def is_connected(src, dst):
    pkt = IP(dst=dst) / ICMP()  # Crea un paquete ICMP (ping) hacia dst
    resp = sr1(pkt, timeout=5, verbose=False)  # Incrementa el tiempo de espera
    return resp is not None  # Devuelve True si hay respuesta, False si no



def get_ip_from_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        print(f"Error al resolver el dominio {domain}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    final_results = {}
    target = args.target
    
    if not target.replace('.', '').isdigit():
        print(f"Resolviendo el dominio {target} a IP...")
        target = get_ip_from_domain(target)
        print(f"Dirección IP obtenida: {target}")

    try:
        best_protocol, best_result, all_results = run_all_protocols(args.target)
        results = {
            "best_protocol": best_protocol,
            "best_result": best_result,
            "all_results": all_results
        }
        
        last_hops = [route["hops"] for route in best_result["routes"] if route["hops"]]
        unique_ips = set(ip for sublist in last_hops for ip in sublist)
        
        # Obtener datos de OSINT y geográficos
        osint_results = get_osint_data(unique_ips)

        # Ejecutar ping para calcular latencia y jitter solo hacia el destino
        ping_results = ping_ip(args.target, count=50)

        origin = best_result["routes"][0]["hops"][0] if best_result["routes"] and best_result["routes"][0]["hops"] else None
        destination = best_result["routes"][-1]["hops"][0] if best_result["routes"] and best_result["routes"][-1]["hops"] else None
        
        all_possible_routes = {}

        if origin and destination:
            all_possible_routes = calculate_all_routes_with_nulls(best_result["routes"], best_result["connections"])
            load_balancing = len(all_possible_routes)
        else:
            load_balancing = 1
        
        route_diversity = calculate_route_diversity(best_result["routes"], best_result["connections"], osint_results)


        best_result["all_possible_routes"] = all_possible_routes
        results["best_result"]["load_balancing"] = load_balancing
        results["best_result"]["route_diversity"] = route_diversity

        results["osint"] = osint_results
        results["ping"] = ping_results

        final_results = {target: results}

    except Exception as e:
        print(f"Error: {e}")

    finally:
        if args.output:
            output_path = os.path.join('output', args.output)
            with open(output_path, 'w') as f:
                json.dump(final_results, f, indent=4, default=str)
            print(f"Resultados guardados en {output_path}")
        else:
            print(json.dumps(final_results, indent=4, default=str))

        # Llamar al script de consolidación de JSON
        print("Ejecutando el script de consolidación de JSON...")
        subprocess.run([sys.executable, 'consolidate_json.py'])
