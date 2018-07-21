# -*- coding: utf-8 -*-
"""
Created on Thu Jun 21 13:54:46 2018

@author: pesu
"""

from socket import *
import string
import random
import hashlib
import json
from Crypto.Cipher import AES
import time

Key_authentication_server_TGS=(hashlib.sha256("Kas_tgs".encode()).hexdigest())[::2]
Key_server_TGS=(hashlib.sha256("Ktgs_b".encode()).hexdigest())[::2]
nonce_list=[]

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

def nonce_list_update():
    current_time=time.time()
    for i in nonce_list:
        if (current_time-i)>120:
            nonce_list.remove(i)

def nonce_valid(nonce):
    nonce_list_update()
    if nonce in nonce_list:
        return 0
    elif (time.time()-nonce)>120:
        return 0
    else:
        nonce_list.append(nonce)
        return 1
  
socket_variable=socket(AF_INET,SOCK_STREAM)
TGS_socket=8001
TGS_address="10.3.30.178"
socket_variable.bind((TGS_address,TGS_socket))
socket_variable.listen(10)

while(True):
    c,client_addr=socket_variable.accept()
    received_data=c.recv(2048)
    received_data=received_data.decode()
    if "nonce" in received_data:
        data_from_client_to_TGS=json.loads(received_data)
        decrypted_ticket=AES_symmetric_key_decrypt(Key_authentication_server_TGS,data_from_client_to_TGS['ticket'])
        decrypted_ticket=json.loads(decrypted_ticket)
        Key_client_TGS=decrypted_ticket['Key_client_TGS'] 
        user_id=decrypted_ticket['user_id']
        nonce=float(AES_symmetric_key_decrypt(Key_client_TGS,data_from_client_to_TGS["nonce"]))
        if nonce_valid(nonce):
            print("received request from user",user_id.upper())
            Key_client_server=randomkeygen()
            ticket_to_client={"Key_client_server":Key_client_server}
            ticket_to_client=json.dumps(ticket_to_client)
            ticket_to_client=AES_symmetric_key_encrypt(Key_client_TGS,ticket_to_client)        
            ticket_to_server={"author":user_id,"Key_client_server":Key_client_server}
            ticket_to_server=json.dumps(ticket_to_server)
            ticket_to_server=AES_symmetric_key_encrypt(Key_server_TGS,ticket_to_server)
            data_from_TGS_to_client={"ticket_to_client":ticket_to_client,"ticket_to_server":ticket_to_server}
            data_from_TGS_to_client=json.dumps(data_from_TGS_to_client)
            print("data_from_TGS_to_client:",data_from_TGS_to_client)
            c.send(data_from_TGS_to_client.encode())
        else:
            reply="error!".encode()
            c.send(reply)
            print("replay attack averted")
            print()
    else:
        reply="error!".encode()
        c.send(reply)
        print("error message sent")