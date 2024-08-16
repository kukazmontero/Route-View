import json
import folium
import sys
from collections import defaultdict

def create_map(data, selected_route, output_file):
    target_ip = list(data.keys())[0]
    ip_info = data[target_ip]['osint']
    
    # Calculate the center of the map
    latitudes = []
    longitudes = []
    for ip, info in ip_info.items():
        try:
            lat = float(info['latitude'])
            lon = float(info['longitude'])
            latitudes.append(lat)
            longitudes.append(lon)
        except (TypeError, ValueError):
            continue

    if latitudes and longitudes:
        map_center = [sum(latitudes) / len(latitudes), sum(longitudes) / len(longitudes)]
    else:
        map_center = [0, 0]

    # Create the map
    m = folium.Map(location=map_center, zoom_start=2)

    # Group IPs by location
    location_groups = defaultdict(list)
    for ip, info in ip_info.items():
        try:
            lat = float(info['latitude'])
            lon = float(info['longitude'])
            location_groups[(lat, lon)].append(ip)
        except (TypeError, ValueError):
            continue

    # Add nodes to the map based on the selected route
    for lat_lon, ips in location_groups.items():
        lat, lon = lat_lon
        popup_info = ""
        for ip in ips:
            if ip in selected_route:
                ttl = selected_route.index(ip) + 1
                popup_info += f"IP: {ip}<br>TTL: {ttl}<br>Latitud: {lat}<br>Longitud: {lon}<br><br>"
        if popup_info:
            folium.Marker(
                location=[lat, lon],
                popup=popup_info,
                icon=folium.Icon(color='blue')
            ).add_to(m)

    # Add connections for the selected route
    selected_route_ips = [ip for ip in selected_route if ip in ip_info]
    for i in range(len(selected_route_ips) - 1):
        start_ip = selected_route_ips[i]
        end_ip = selected_route_ips[i + 1]
        if start_ip in ip_info and end_ip in ip_info:
            try:
                start_lat = float(ip_info[start_ip]['latitude'])
                start_lon = float(ip_info[start_ip]['longitude'])
                end_lat = float(ip_info[end_ip]['latitude'])
                end_lon = float(ip_info[end_ip]['longitude'])
                folium.PolyLine(
                    locations=[
                        [start_lat, start_lon],
                        [end_lat, end_lon]
                    ],
                    color='blue'
                ).add_to(m)
            except (TypeError, ValueError):
                continue

    # Save the map
    m.save(output_file)

if __name__ == "__main__":
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
    selected_route = json.loads(sys.argv[2])
    output_file = sys.argv[3]
    create_map(data, selected_route, output_file)
