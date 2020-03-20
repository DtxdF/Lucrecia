# Lucrecia
<p align="left">
    <img src="img/LucreciaLogo.jpg" width="500" height="500">
    <br><br>
    <img src="https://img.shields.io/badge/Hecho%20en-Python3-orange">
    <a href="https://github.com/Kirari-Senpai"><img src="https://img.shields.io/badge/Creado%20por-Kirari-green"></a>
    <a href="https://github.com/Kirari-Senpai?tab=repositories"><img src="https://img.shields.io/badge/Ver%20m%C3%A1s-repositorios-yellow"></a>
    <br><br>
    
Lucrecia es un simple honeypot de media interacción para atacantes con servicio FTP.
</p>

## Clonar el repositorio ##

```
git clone https://github.com/Kirari-Senpai/Lucrecia.git
```

## Instalar dependencias ##

```
pip3 install -r requirements.txt
```

## Configurar servidor ##

Abrimos el archivo "server.conf" con el editor que les parezca más cómodo. Entonces editan como más les guste:

```
[DEFAULT]

HOST = 0.0.0.0
PORT = 21


[FTP]

USER = test
PASSWORD = test

```

## Uso de Lucrecia Honeypot ##

<img src="img/img1.png" height="600" width="635">
