# Usar una imagen base de Python
FROM python:3.9-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el resto de los archivos de la aplicación al contenedor
COPY . .

# Instalar las dependencias individualmente
RUN pip install --no-cache-dir Flask
RUN pip install --no-cache-dir requests
RUN pip install --no-cache-dir scapy
RUN pip install --no-cache-dir python-nmap
RUN pip install --no-cache-dir python-whois
RUN pip install --no-cache-dir python-dotenv
RUN pip install --no-cache-dir pythonping
RUN pip install --no-cache-dir censys
RUN pip install --no-cache-dir folium

# Exponer el puerto 5000 para Flask
EXPOSE 5000

# Comando para ejecutar la aplicación Flask
CMD ["python", "app.py"]
