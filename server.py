#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Jun 23 03:51:09 2018

@author: amogh
"""

from socket import *
import json
import hashlib
from Crypto.Cipher import AES
#import asymmetric_key_decryption
import blockchain_code
import time
import math

Key_server_TGS=(hashlib.sha256("Ktgs_b".encode()).hexdigest())[::2]

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
server_socket=9001
server_address="10.3.30.46"
socket_variable.bind((server_address,server_socket))
socket_variable.listen(10)

while(True):
    c,client_address=socket_variable.accept()
    data_from_client_to_server=c.recv(2048).decode()
    if 'nonce' in data_from_client_to_server:
        data_from_client_to_server=json.loads(data_from_client_to_server)
        decrypted_ticket=AES_symmetric_key_decrypt(Key_server_TGS,data_from_client_to_server['ticket'])
        decrypted_ticket=json.loads(decrypted_ticket)
        Key_client_server=decrypted_ticket['Key_client_server']
        center_id=decrypted_ticket['author']
        print("request to send fingerprints from center",center_id.upper())
        nonce=AES_symmetric_key_decrypt(Key_client_server,data_from_client_to_server['nonce'])
        return_nonce=str(float(nonce)-1)
        return_nonce=AES_symmetric_key_encrypt(Key_client_server,return_nonce)
        c.send(return_nonce.encode())
        print("returned_encrypted_nonce",return_nonce)
        len_data=c.recv(2048).decode()
        len_data=int(len_data)
        no_of_iters=math.ceil(len_data/2048)
        time.sleep(0.5)
        verification_from_client=b''
        for i in range(no_of_iters):
            verification_from_client1=c.recv(2048)
            verification_from_client+=verification_from_client1
        verification_from_client=verification_from_client.decode()
        if verification_from_client=="error! invalid return of nonce":
            print("error in communication. Connection terminated")
        else:
            verification_from_client=AES_symmetric_key_decrypt(Key_client_server,verification_from_client)
            if 'user_id' in verification_from_client:
                verification_from_client=json.loads(verification_from_client)
                reply=AES_symmetric_key_encrypt(Key_client_server,"accepted").encode()
                c.send(reply)
                print("fingerprints successfully accepted")
                new_transaction=blockchain_code.Transaction(verification_from_client['user_id'],center_id,verification_from_client['list_of_fingerprints'],time.time())
                print("fingerprint data:",verification_from_client)
            else:
               reply=AES_symmetric_key_encrypt(Key_client_server,"error!").encode()
               c.send(reply)
               print("invalid data received")             
    else:
        reply="error!".encode()
        c.send(reply)
        print("error message sent")