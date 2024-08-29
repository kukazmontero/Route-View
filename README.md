# Guía de Instalación de Route-View

Para ejecutar el software **Route-View**, sigue estos pasos:

## 1. Instalar Docker

Primero, necesitas tener Docker instalado en tu sistema. Puedes descargar e instalar Docker desde [aquí](https://www.docker.com/).

## 2. Clonar el Repositorio

Clona el repositorio de Route-View usando Git. Abre una terminal y ejecuta el siguiente comando:

```
git clone https://github.com/kukazmontero/Route-View.git
```
## 3. Construir la Imagen Docker

Navega al directorio del repositorio clonado y crea la imagen de Docker para Route-View. Asegúrate de tener permisos de administrador y ejecuta el siguiente comando:

```
docker build -t route .
```
## 4. Ejecutar el Contenedor

Finalmente, ejecuta el proyecto en un contenedor Docker con los permisos de red necesarios. Usa el siguiente comando:

```
docker run --rm -it --network host --cap-add NET_ADMIN --cap-add NET_RAW route
```

## 5. Notas

 ● El tiempo de ejecución predeterminado entre cada modalidad (UDP, ICMP y TCP) es de 10 segundos. Este parámetro puede modificarse en la variable INTERVAL, ubicada en la línea 42 del archivo route_view.py.

 ● Para obtener información pública de los nodos descubiertos, es necesario reemplazar el API ID y la API KEY de [Censys](https://search.censys.io/), que están predefinidos en la línea 322 del archivo route_view.py. Para ello, debes registrarte en la plataforma, acceder a "Mi cuenta" y luego a la sección de API.
