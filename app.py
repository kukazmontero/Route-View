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
        
        # Generar el mapa
        subprocess.run([sys.executable, 'generate_map.py', 'output/consolidated_output.json', 'static/generated_map.html'])
        
        return render_template('resultados.html')
    
    return render_template('index.html')

@app.route('/resultados', methods=['GET'])
def resultados():
    if not os.path.exists('static/generated_map.html'):
        try:
            # Asegúrate de que el archivo consolidated_output.json existe
            if os.path.exists('output/consolidated_output.json'):
                subprocess.run([sys.executable, 'generate_map.py', 'output/consolidated_output.json', 'static/generated_map.html'])
            else:
                return jsonify({"status": "error", "message": "consolidated_output.json not found"}), 404
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
    return render_template('resultados.html')

@app.route('/data', methods=['GET'])
def get_data():
    with open('output/consolidated_output.json', 'r') as f:
        data = json.load(f)
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
