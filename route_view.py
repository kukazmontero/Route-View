import os
import sys
import argparse
import json
import time
from scapy.all import *
from scapy.layers.inet import ICMP, UDP, IP, TCP
import nmap
import whois
import subprocess
from censys.search import CensysHosts
from dotenv import load_dotenv
from zoomeye.sdk import ZoomEye
from datetime import datetime
import math
import random


# Configuración para utilizar api.zoomeye.hk
class CustomZoomEye(ZoomEye):
    def __init__(self, api_key=None):
        super().__init__(api_key)
        self.api_base = "https://api.zoomeye.hk"

# Cargar variables de entorno
load_dotenv()

# Configuración de credenciales
ZOOMEYE_API_KEY = os.getenv('36D9F177-4798-977ca-3068-372ffa313cd')

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
PORT_RANGE_END = 33439
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

    while ttl <= MAX_HOPS and not destination_reached:
        hops = set()
        success_count = 0
        probes_sent = 0

        while probes_sent < MAX_PROBES:
            reply = send_probe_icmp(target, ttl)
            probes_sent += 1

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
                    success_count += 1

            # Ajustar el número de probes necesarios dinámicamente
            success_rate = success_count / probes_sent
            probes_needed = calculate_probes_needed(CONFIDENCE_LEVEL, success_rate)
            if success_count >= probes_needed:
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

    return routes, connections

def trace_mda_udp(dest_ip):
    def explore_paths(dest_ip, ttl, dport, max_probes, max_paths):
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

    ttl = TTL_START
    routes = []
    connections = {}
    destination_reached = False
    consecutive_failures = 0

    while ttl <= max_ttl and not destination_reached:
        paths = explore_paths(dest_ip, ttl, PORT_RANGE_START, probes_per_ttl, MAX_PROBES)
        hops = list(paths.keys())
        success_count = len(hops)

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

        success_rate = success_count / probes_per_ttl
        probes_needed = calculate_probes_needed(CONFIDENCE_LEVEL, success_rate)
        print(f"TTL {ttl} alcanzado en {hops}")

        ttl += 1

    return routes, connections

def trace_mda_tcp(target_ip):
    ttl = TTL_START
    routes = []
    connections = {}
    destination_reached = False
    consecutive_failures = 0

    while ttl <= max_ttl and not destination_reached:
        hops = set()
        success_count = 0

        for _ in range(probes_per_ttl):
            reply = send_probe_tcp(target_ip, ttl, PORT_RANGE_START)
            if reply is not None:
                if reply.haslayer(ICMP):
                    icmp_type = reply.getlayer(ICMP).type
                    if icmp_type == 11:  # Time-to-live exceeded
                        hops.add(reply.src)
                        success_count += 1
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

        success_rate = success_count / probes_per_ttl
        probes_needed = calculate_probes_needed(CONFIDENCE_LEVEL, success_rate)
        print(f"TTL {ttl} alcanzado en {hops}")

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
        if protocol == "icmp":
            routes, connections = trace_mda_icmp(target)
        elif protocol == "udp":
            routes, connections = trace_mda_udp(target)
        elif protocol == "tcp":
            routes, connections = trace_mda_tcp(target)
        total_hops = len(routes)
        total_ips = sum(1 for route in routes if route["hops"])
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

    return best_protocol, best_result, results

def get_censys_data(ip):
    try:
        time.sleep(1)
        h = CensysHosts(api_id="3be9e6a3-2830-4fa7-b144-8a586c38e653", api_secret="EpuyKecOZjrvg2nZ9RfySfkbVOVeEis9")
        host = h.view(ip)
        return host
    except Exception as e:
        print(f"Error obteniendo datos de Censys para IP {ip}: {e}")
        return {}

# Función para obtener datos de ZoomEye usando el comando CLI
def get_zoomeye_data(ip):
    try:
        result = subprocess.run(["zoomeye", "ip", ip], capture_output=True, text=True)
        return parse_zoomeye_output(result.stdout)
    except Exception as e:
        print(f"Error obteniendo datos de ZoomEye para IP {ip}: {e}")
        return {}

# Función para parsear la salida de ZoomEye
def parse_zoomeye_output(output):
    lines = output.splitlines()
    if not lines or "Hostnames" not in lines[1]:
        return {"error": "No data available"}

    data = {
        "Hostnames": lines[1].split(":")[1].strip(),
        "Isp": lines[2].split(":")[1].strip(),
        "Country": lines[3].split(":")[1].strip(),
        "City": lines[4].split(":")[1].strip(),
        "Organization": lines[5].split(":")[1].strip(),
        "Lastupdated": lines[6].split(":")[1].strip(),
        "Number of open ports": lines[7].split(":")[1].strip(),
        "Ports": []
    }

    for line in lines[10:]:
        parts = line.split()
        if len(parts) >= 4:
            port_info = {
                "port": parts[0],
                "service": parts[1],
                "app": parts[2],
                "banner": " ".join(parts[3:])
            }
            data["Ports"].append(port_info)

    return data

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
    for ip in ip_list:
        censys_data = get_censys_data(ip)
        zoomeye_data = get_zoomeye_data(ip)
        nmap_data = get_nmap_data(ip)
        whois_data = get_whois_data(ip)
        osint_results[ip] = {
            "censys": censys_data,
            "zoomeye": zoomeye_data,
            "nmap": nmap_data,
            "whois": whois_data
        }
    return osint_results

if __name__ == "__main__":
    final_results = {}
    try:
        best_protocol, best_result, all_results = run_all_protocols(args.target)
        results = {
            "best_protocol": best_protocol,
            "best_result": best_result,
            "all_results": all_results
        }
        
        last_hops = [route["hops"] for route in best_result["routes"] if route["hops"]]
        unique_ips = set(ip for sublist in last_hops for ip in sublist)
        
        osint_results = get_osint_data(unique_ips)
        
        results["osint"] = osint_results

        final_results = {args.target: results}

    except Exception as e:
        print(f"Error: {e}")

    finally:
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(final_results, f, indent=4, default=str)
            print(f"Resultados guardados en {args.output}")
        else:
            print(json.dumps(final_results, indent=4, default=str))
