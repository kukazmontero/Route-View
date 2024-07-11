from flask import Flask, render_template, request, jsonify
import subprocess
import json
import os
import sys

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form.get('target')
        if not target:
            return jsonify({"status": "error", "message": "Target is required"}), 400
        
        # Ejecutar el script principal
        subprocess.run([sys.executable, 'route_view.py', '-t', target, '-o', 'output.json'])

        return render_template('resultados.html')
    
    return render_template('index.html')

@app.route('/resultados', methods=['GET'])
def resultados():
    if not os.path.exists('static/generated_map.html'):
        try:
            subprocess.run([sys.executable, 'generate_map.py', 'output/consolidated_output.json', 'static/generated_map.html'])
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
    return render_template('resultados.html')

@app.route('/update_map', methods=['POST'])
def update_map():
    data = request.json
    selected_route = data.get('selected_route')
    if not selected_route:
        return jsonify({"status": "error", "message": "Selected route is required"}), 400
    with open('output/consolidated_output.json', 'r') as f:
        consolidated_data = json.load(f)
    subprocess.run([sys.executable, 'generate_map.py', 'output/consolidated_output.json', json.dumps(selected_route), 'static/generated_map.html'])
    return jsonify({"status": "success"})

@app.route('/ip_info', methods=['POST'])
def ip_info():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({"status": "error", "message": "IP is required"}), 400
    with open('output/consolidated_output.json', 'r') as f:
        consolidated_data = json.load(f)
    target_ip = list(consolidated_data.keys())[0]
    ip_info = consolidated_data[target_ip]['osint'].get(ip, {})
    return jsonify(ip_info)

@app.route('/data', methods=['GET'])
def get_data():
    with open('output/consolidated_output.json', 'r') as f:
        data = json.load(f)
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
