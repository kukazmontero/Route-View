Pasos para ejecutar Route-View

Desde una terminal con permisos de administrador, generamos la imagen de docker

```
  docker build -t route .
```

EJecutamos el proyecto con los permisos de red necesarios

```
  docker run --rm -it --network host --cap-add NET_ADMIN --cap-add NET_RAW route  
```
