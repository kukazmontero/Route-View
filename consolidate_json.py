import json

# Función para consolidar información OSINT por IP
def consolidate_osint_data(ip, osint_data):
    consolidated_data = {}
    
    # Información geográfica
    geo_info = osint_data.get("geo", {})
    censys_info = osint_data.get("censys", {}).get("location", {})
    consolidated_data["latitude"] = geo_info.get("latitude") or censys_info.get("coordinates", {}).get("latitude")
    consolidated_data["longitude"] = geo_info.get("longitude") or censys_info.get("coordinates", {}).get("longitude")
    consolidated_data["city"] = geo_info.get("city") or censys_info.get("city")
    consolidated_data["country"] = geo_info.get("country") or censys_info.get("country")
    consolidated_data["province"] = geo_info.get("province") or censys_info.get("province")

    # Información de sistema autónomo
    as_info = osint_data.get("censys", {}).get("autonomous_system", {})
    consolidated_data["asn"] = as_info.get("asn")
    consolidated_data["asn_description"] = as_info.get("description")
    consolidated_data["bgp_prefix"] = as_info.get("bgp_prefix")
    consolidated_data["asn_name"] = as_info.get("name")

    # Puertos abiertos y servicios
    consolidated_data["open_ports"] = []
    for source in ["nmap", "censys"]:
        ports_info = osint_data.get(source, {}).get("services", [])
        for port in ports_info:
            if port.get("port"):
                consolidated_data["open_ports"].append({
                    "port": port.get("port"),
                    "service": port.get("extended_service_name") or port.get("name"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                    "extra_info": port.get("extrainfo")
                })

    # Información adicional de Nmap
    nmap_info = osint_data.get("nmap", {})
    consolidated_data["os"] = nmap_info.get("osclass", [{}])[0].get("osfamily")
    consolidated_data["mac_address"] = nmap_info.get("addresses", {}).get("mac")

    # Información de Whois
    whois_info = osint_data.get("whois", {})
    consolidated_data["whois"] = {
        "domain_name": whois_info.get("domain_name"),
        "registrar": whois_info.get("registrar"),
        "whois_server": whois_info.get("whois_server"),
        "referral_url": whois_info.get("referral_url"),
        "updated_date": whois_info.get("updated_date"),
        "creation_date": whois_info.get("creation_date"),
        "expiration_date": whois_info.get("expiration_date"),
        "name_servers": whois_info.get("name_servers"),
        "status": whois_info.get("status"),
        "emails": whois_info.get("emails"),
        "dnssec": whois_info.get("dnssec"),
        "name": whois_info.get("name"),
        "org": whois_info.get("org"),
        "address": whois_info.get("address"),
        "city": whois_info.get("city"),
        "state": whois_info.get("state"),
        "registrant_postal_code": whois_info.get("registrant_postal_code"),
        "country": whois_info.get("country")
    }

    # Información de ZoomEye
    zoomeye_info = osint_data.get("zoomeye", {})
    if "error" not in zoomeye_info:
        consolidated_data["zoomeye"] = zoomeye_info

    return consolidated_data

# Cargar el JSON de entrada
with open('output/output.json', 'r') as f:
    data = json.load(f)

# Preparar la estructura del JSON final
final_results = {}
target = list(data.keys())[0]
best_protocol = data[target]["best_protocol"]
best_result = data[target]["best_result"]
osint_data = data[target]["osint"]

final_results[target] = {
    "best_protocol": best_protocol,
    "best_result": best_result,
    "osint": {}
}

# Consolidar la información OSINT
for ip, osint_info in osint_data.items():
    final_results[target]["osint"][ip] = consolidate_osint_data(ip, osint_info)

# Añadir la información de ping
final_results[target]["ping"] = data[target].get("ping", {})

# Guardar el JSON final
with open('output/consolidated_output.json', 'w') as f:
    json.dump(final_results, f, indent=4)

print("JSON consolidado guardado en 'consolidated_output.json'")
