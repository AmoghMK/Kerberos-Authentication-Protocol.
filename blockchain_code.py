# -*- coding: utf-8 -*-
"""
Created on Mon Jun 11 21:36:20 2018

@author: Amogh
"""
from hashlib import sha256
import json
import time
import encrypt
import decrypt

def encrypt_func (features_list):
    e_features_list=[]
    for i in features_list:
        e_features_list.append(str(encrypt.encrypt_blob(i.encode(), encrypt.public_key)))
    return(e_features_list)    
    
class Transaction:
    def __init__(self,user_id,author,features_list,timestamp):
        self.user_id=user_id
        self.author=author
        self.e_features_list=encrypt_func(features_list)
        self.hashval=sha256((json.dumps(self.e_features_list, sort_keys=True)).encode()).hexdigest()
        self.hashval=str(encrypt.encrypt_blob((self.hashval).encode(),decrypt.private_key))
        self.timestamp=timestamp
        
        
class Block:
    
    nonce=0
    
    def __init__(self,index,transactions,timestamp,previous_hash):
        self.index = index
        self.transactions = transactions 
        self.timestamp = timestamp
        self.previous_hash=previous_hash
        
    def compute_hash(self):
        l=[]
        for i in self.transactions:
            l.append(sha256((json.dumps(i.__dict__,sort_keys=True)).encode()).hexdigest())
        while len(l)>1:
            l.append(sha256((l.pop(0)+l.pop(1)).encode()).hexdigest())
        l.append([self.nonce,self.index,self.previous_hash,self.timestamp]) 
        return sha256((json.dumps(l, sort_keys=True)).encode()).hexdigest()
    
class Blockchain:
    
    difficulty=1
    
    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0")
        genesis_block.hash = self.proof_of_work(genesis_block)
        self.chain.append(genesis_block)
        
    def last_block(self):
        return self.chain[-1]
    
    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            print(computed_hash)
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash
    
    def add_block(self, block, proof):
        previous_hash = self.last_block().hash
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block)
        return True
 
    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * Blockchain.difficulty) and block_hash == block.compute_hash())
    
    def add_new_transaction(self, transaction):
            self.unconfirmed_transactions.append(transaction)
 
    def mine(self):
        #if not self.unconfirmed_transactions:
        #    return False
        new_block = Block(self.last_block().index + 1,
                          self.unconfirmed_transactions,
                          time.time(),
                          self.last_block().hash)
        proof = self.proof_of_work(new_block)
        if (self.add_block(new_block, proof)):
            self.unconfirmed_transactions = []
        
