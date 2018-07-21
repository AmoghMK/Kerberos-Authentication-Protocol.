# -*- coding: utf-8 -*-
"""
Created on Thu Jun 21 09:25:15 2018

@author: pesu
"""

from socket import *
import string 
import random 
import hashlib
import json
from Crypto.Cipher import AES

Key_authentication_server_TGS=(hashlib.sha256("Kas_tgs".encode()).hexdigest())[::2]

user_password_database={'alice':'hello','cathy':'password'}

def randomkeygen():
    n=random.randint(1,16)
    s=''
    for i in range(n):
        s=s+random.choice(string.ascii_letters)
    s=hashlib.sha256(s.encode()).hexdigest()
    return(s[::2])   

'''
def en_de_crypt (key,data):
    kl=len(key)
    dl=len(data)
    s=''
    for i in range(dl):
        s=s+chr(ord(key[i%kl])^ord(data[i]))
    return(s)
'''

def padremove(data):
    flag=1
    i=len(data)-1
    while(flag==1 and i>=0):
        if (data[i]=='0'):
            i-=1
        elif (data[i]=='1'):
            flag=0
        else:
            flag=-1
    if flag==0:
        return(data[:i])
    else:
        return(data)

def AES_symmetric_key_encrypt(key,data):
    cipher=AES.new(key,AES.MODE_ECB)
    datalength=len(data)
    padlength=(16-datalength%16)
    data=data+'1'+'0'*(padlength-1)
    encrypted_data=cipher.encrypt(data)
    encrypted_data="".join(map(chr,list(encrypted_data)))
    return (encrypted_data)

def AES_symmetric_key_decrypt(key,data):
    cipher=AES.new(key,AES.MODE_ECB)
    data=bytes(list(map(ord,list(data))))
    decrypted_data=cipher.decrypt(data).decode()
    return (padremove(decrypted_data))

socket_variable=socket(AF_INET,SOCK_STREAM)
authentication_server_socket=7000
authentication_server_address="10.3.30.208"
socket_variable.bind((authentication_server_address,authentication_server_socket))
socket_variable.listen(10)

while(True):
    c,client_address=socket_variable.accept()
    received_data=c.recv(2048)
    received_data=received_data.decode()
    if received_data in user_password_database.keys():
        print("received request from user",received_data.upper())
        password=user_password_database[received_data]
        Key_client_authentication_server=(hashlib.sha256(password.encode()).hexdigest())[::2]
        Key_client_TGS=randomkeygen()
        ticket_to_TGS={'user_id':received_data,'Key_client_TGS':Key_client_TGS}
        ticket_to_TGS=json.dumps(ticket_to_TGS)
        ticket_to_TGS=AES_symmetric_key_encrypt(Key_authentication_server_TGS,ticket_to_TGS)
        data_from_authentication_server_to_client={'Key_client_TGS':Key_client_TGS,'ticket_to_TGS':ticket_to_TGS}
        data_from_authentication_server_to_client=json.dumps(data_from_authentication_server_to_client)
        print("data_from_authentication_server_to_client: ",data_from_authentication_server_to_client)
        data_from_authentication_server_to_client=AES_symmetric_key_encrypt(Key_client_authentication_server,data_from_authentication_server_to_client)    
        print("encrypted_data_from_authentication_server_to_client: ",data_from_authentication_server_to_client)        
        c.send(data_from_authentication_server_to_client.encode())     
    else:
        reply="error!".encode()
        c.send(reply)
        print("error message sent")
    
