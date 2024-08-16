FROM python:3

# Establece el directorio de trabajo
WORKDIR .

# Instala Nmap y otras dependencias necesarias
RUN apt-get update && \
    apt-get install -y nmap && \
    apt-get clean

# Copia el archivo de requisitos
COPY requirements.txt .

# Instala las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copia el código fuente de la aplicación
COPY . .

# Expone el puerto en el que Flask estará escuchando
EXPOSE 5000

# Comando para iniciar la aplicación
CMD ["python", "app.py"]