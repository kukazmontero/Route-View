from flask import Flask, render_template, request, jsonify
import subprocess
import json
import os
import sys

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form['target']
        # Ejecutar el script principal
        subprocess.run([sys.executable, 'route_view.py', '-t', target, '-o', 'output.json'])
        return jsonify({"status": "success"})
    return render_template('index.html')

@app.route('/data', methods=['GET'])
def get_data():
    # Asegurarse de que la carpeta output existe
    os.makedirs('output', exist_ok=True)
    
    with open('output/consolidated_output.json', 'r') as f:
        data = json.load(f)
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
