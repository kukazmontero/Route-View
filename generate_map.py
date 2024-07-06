import folium
import json
import sys
from folium.features import CustomIcon

def create_map(data, output_file):
    # Crear un mapa centrado en un punto
    m = folium.Map(location=[0, 0], zoom_start=2)

    # Agregar los puntos al mapa
    for ip, info in data.items():
        if 'osint' not in info:
            continue
        osint_data = info['osint']
        best_result = info['best_result']
        routes = best_result['routes']
        
        for route in routes:
            ttl = route['ttl']
            hops = route['hops']
            for hop in hops:
                if hop in osint_data:
                    osint_info = osint_data[hop]
                    lat = osint_info.get('latitude')
                    lon = osint_info.get('longitude')
                    if lat and lon:
                        popup_text = f"IP: {hop}<br>TTL: {ttl}"
                        if osint_info.get('city'):
                            popup_text += f"<br>City: {osint_info['city']}"
                        if osint_info.get('country'):
                            popup_text += f"<br>Country: {osint_info['country']}"
                        if osint_info.get('asn'):
                            popup_text += f"<br>ASN: {osint_info['asn']}"
                        if osint_info.get('asn_description'):
                            popup_text += f"<br>ASN Description: {osint_info['asn_description']}"
                        if osint_info.get('bgp_prefix'):
                            popup_text += f"<br>BGP Prefix: {osint_info['bgp_prefix']}"
                        folium.Marker(
                            location=[float(lat), float(lon)],
                            popup=popup_text,
                            icon=folium.Icon(color='blue')
                        ).add_to(m)

    # Agregar las conexiones al mapa
    for source, targets in best_result['connections'].items():
        if source in osint_data:
            source_info = osint_data[source]
            source_lat = source_info.get('latitude')
            source_lon = source_info.get('longitude')
            if source_lat and source_lon:
                for target in targets:
                    if target in osint_data:
                        target_info = osint_data[target]
                        target_lat = target_info.get('latitude')
                        target_lon = target_info.get('longitude')
                        if target_lat and target_lon:
                            folium.PolyLine(
                                locations=[(float(source_lat), float(source_lon)), (float(target_lat), float(target_lon))],
                                color='black'
                            ).add_to(m)

    # Guardar el mapa en un archivo HTML
    m.save(output_file)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python generate_map.py <input_json> <output_html>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, 'r') as f:
        data = json.load(f)

    # Ejecutar la función para crear el mapa
    create_map(data, output_file)
