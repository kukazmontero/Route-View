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

	
