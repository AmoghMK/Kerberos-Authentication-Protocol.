# -*- coding: utf-8 -*-
"""
Created on Thu Jun 21 09:24:54 2018

@author: pesu
"""

from socket import *
import hashlib
import time
import json
from Crypto.Cipher import AES
import math

'''
def en_de_crypt(key, data):
    kl=len(key)
    dl=len(data)
    s=''
    for i in range(dl):
        s=s+chr(ord(key[i%kl])^ord(data[i]))
    return s
'''

def padremove(data):
    flag=1
    i=len(data)-1
    while(flag==1 and i>0):
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
    return(encrypted_data)

def AES_symmetric_key_decrypt(key,data):
    cipher=AES.new(key,AES.MODE_ECB)
    data=bytes(list(map(ord,list(data))))
    decrypted_data=cipher.decrypt(data).decode()
    return(padremove(decrypted_data))

def contact_authentication_server():
    flag=1
    while(flag):
        socket_variable=socket(AF_INET,SOCK_STREAM)
        authentication_server_socket=7000
        authentication_server_address="10.3.30.208"
        socket_variable.connect((authentication_server_address,authentication_server_socket))
        data_from_client_to_authentication_server=input("enter user name:")
        socket_variable.send(data_from_client_to_authentication_server.encode())
        data_from_authentication_server_to_client=socket_variable.recv(2048).decode()
        if data_from_authentication_server_to_client == "error!":
            print("invalid username, try again")             
            time.sleep(0.1)
        else:
            flag=0
        socket_variable.close() 
    print("received encrypted message")
    time.sleep(0.1)
    flag=1
    while(flag):
        password=input("enter your password to decrypt:")
        Key_client_authentication_server=(hashlib.sha256(password.encode()).hexdigest())[::2]
        try:        
            data_from_authentication_server_to_client_decrypted = AES_symmetric_key_decrypt(Key_client_authentication_server,data_from_authentication_server_to_client)
        except UnicodeDecodeError:
            print("incorrect password, try again")
            continue
        if "Key_client_TGS" not in data_from_authentication_server_to_client_decrypted:
            print("incorrect password, try again")    
        else:
            flag=0
            print("decrypted message:", data_from_authentication_server_to_client_decrypted)
    data_from_authentication_server_to_client_decrypted=json.loads(data_from_authentication_server_to_client_decrypted)
    Key_client_TGS=data_from_authentication_server_to_client_decrypted['Key_client_TGS']
    print("Session key between client and TGS server:",Key_client_TGS)
    ticket_to_TGS=data_from_authentication_server_to_client_decrypted['ticket_to_TGS']
    return([Key_client_TGS,ticket_to_TGS])
    
def contact_TGS(Key_client_TGS,ticket_to_TGS,nonce):
    data_from_client_to_TGS = {'nonce':AES_symmetric_key_encrypt(Key_client_TGS,str(nonce)),'ticket':ticket_to_TGS}
    socket_variable=socket(AF_INET,SOCK_STREAM)
    TGS_socket=8001
    TGS_address="10.3.30.178"
    socket_variable.connect((TGS_address,TGS_socket))
    data_from_client_to_TGS=json.dumps(data_from_client_to_TGS)
    socket_variable.send(data_from_client_to_TGS.encode())
    print("message sent:",data_from_client_to_TGS)
    data_from_TGS_to_client=socket_variable.recv(2048)
    socket_variable.close()
    data_from_TGS_to_client=data_from_TGS_to_client.decode()
    if "ticket_to_client" not in data_from_TGS_to_client:
        print("error while contacting TGS")
        return(["error!","error!"])
    else:
        print("received message:",data_from_TGS_to_client)
        data_from_TGS_to_client=json.loads(data_from_TGS_to_client)
        ticket_to_client=AES_symmetric_key_decrypt(Key_client_TGS,data_from_TGS_to_client["ticket_to_client"])
        ticket_to_server=data_from_TGS_to_client["ticket_to_server"]
        ticket_to_client=json.loads(ticket_to_client)       
        Key_client_server = ticket_to_client["Key_client_server"]
        print("Session key between client and server:",Key_client_server)
        return([Key_client_server,ticket_to_server])
        
def contact_server(Key_client_server,ticket_to_server,nonce,fingerprint_data_from_client_to_server):
    socket_variable=socket(AF_INET,SOCK_STREAM)
    server_socket=9001
    server_address="10.3.30.46"
    socket_variable.connect((server_address,server_socket))
    data_from_client_to_server1={'nonce':AES_symmetric_key_encrypt(Key_client_server,str(nonce)),'ticket':ticket_to_server}
    data_from_client_to_server1=json.dumps(data_from_client_to_server1)
    socket_variable.send(data_from_client_to_server1.encode())
    print("nonce and ticket sent:",data_from_client_to_server1)
    time.sleep(0.5)
    verification_from_server1=socket_variable.recv(2048)
    verification_from_server1=verification_from_server1.decode()
    verification_from_server1_decrypted=AES_symmetric_key_decrypt(Key_client_server,verification_from_server1)
    print("verification:",verification_from_server1_decrypted)
    time.sleep(0.5) 
    data_from_client_to_server2=AES_symmetric_key_encrypt(Key_client_server,fingerprint_data_from_client_to_server)    
    errorflag=0    
    if verification_from_server1_decrypted != str(nonce-1):
        print("invalid return of nonce, error contacting server")
        data_from_client_to_server2="error! invalid return of nonce"
        errorflag=1
    else:
        print("fingerprint_data_from_client_to_server:",fingerprint_data_from_client_to_server) 
        print("data_from_client_to_server2:",data_from_client_to_server2)
        print("\n\n",len(data_from_client_to_server2),'\n')
    time.sleep(0.5)
    data_from_client_to_server2=data_from_client_to_server2.encode()
    len_data=len(data_from_client_to_server2)
    socket_variable.send(str(len_data).encode())
    time.sleep(0.5)
    no_of_iters=math.floor(len_data/2048)
    #print('no_of_iters:',no_of_iters)
    time.sleep(0.5)    
    i=0
    if (no_of_iters > 0):
        for i in range(no_of_iters):
            socket_variable.send(data_from_client_to_server2[i*2048:(i+1)*2048])
            time.sleep(0.1)
        socket_variable.send(data_from_client_to_server2[(i+1)*2048:])
        time.sleep(0.5)
    else: 
         socket_variable.send(data_from_client_to_server2)    
    print("message sent")
    if (errorflag):
        socket_variable.close()
        return
    else:
        verification_from_server2=socket_variable.recv(2048).decode()
        verification_from_server2_decrypted=AES_symmetric_key_decrypt(Key_client_server,verification_from_server2)
        socket_variable.close()    
        if verification_from_server2_decrypted=="accepted":
            print("fingerprint data sent successfully")
        else:
            print("error in sending fingerprints")
        return
    
    
    
def obtain_fingerprint(user_id):
    list_of_fingerprints=[]
    for i in range(1,9):
        filename='/home/pesu/Desktop/Amogh/fingerprint_features/' + str(user_id) + '_' + str(i) + '.txt'
        filehandle=open(filename,"r")
        list_of_fingerprints.append(filehandle.read())
        filehandle.close()
    return (list_of_fingerprints)


print("Contacting authentication server:")
[Key_client_TGS,ticket_to_TGS]=contact_authentication_server()
print("\nContacting TGS server:")
nonce=time.time()
[Key_client_server,ticket_to_server]=contact_TGS(Key_client_TGS,ticket_to_TGS,nonce)
if [Key_client_server,ticket_to_server] != ["error!","error!"]:
    time.sleep(0.5)
    print("\nContacting server:")
    time.sleep(0.1)
    user_id=int(input("enter user id:"))
    list_of_fingerprints=obtain_fingerprint(user_id)
    fingerprint_data_from_client_to_server={'user_id':user_id,'list_of_fingerprints':list_of_fingerprints}
    fingerprint_data_from_client_to_server=json.dumps(fingerprint_data_from_client_to_server)
    contact_server(Key_client_server,ticket_to_server,nonce,fingerprint_data_from_client_to_server)

