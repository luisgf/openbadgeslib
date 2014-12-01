#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014, Luis Gonzalez Fernandez, All rights reserved.

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 3.0 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library.
"""
"""   
    KeyPair Creation
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141201
    Version:  0.1

"""
import os
import sys

from Crypto.PublicKey import RSA  
from ecdsa import SigningKey, VerifyingKey, NIST256p

# Local imports
from openbadgeslib.errors import UnknownKeyType, PrivateKeySaveError, PublicKeySaveError, PrivateKeyExists, GenPrivateKeyError, GenPublicKeyError, PrivateKeyReadError

class KeyFactory():
    """ Key Factory Object, Return a Given object type passing a name
        to the constructor. """
        
    def __new__(cls, config):
        if config['keys']['crypto'] == 'ECC':
            return KeyECC(config)
        if config['keys']['crypto'] == 'RSA':
            return KeyRSA(config)
        else:
            raise UnknownKeyType()
        
class KeyBase():       
    def __init__(self, config):        
        self.conf = config         
        self.priv_key = None              # crypto Object
        self.pub_key = None               # crypto Object             

    def get_privkey_path(self):
        """ Return de path to the private key """
        return self.conf['keys']['private']
    
    def get_pubkey_path(self):
        """ Return de path to the public key """
        return self.conf['keys']['public']
    
    def save_keypair(self, private_key_pem, public_key_pem):      
        """ Save keypair to file """        
        try:
            with open(self.get_privkey_path(), "wb") as priv:
                priv.write(private_key_pem)
                priv.close()                
        except FileNotFoundError:
             raise PrivateKeySaveError()
         
        try:
            with open(self.get_pubkey_path(), "wb") as pub:
                pub.write(public_key_pem)                    
                pub.close()                
        except FileNotFoundError:
             raise PublicKeySaveError() 

    def has_key(self):
        """ Check if a private key is already generated """
        
        if os.path.isfile(self.get_privkey_path()):
            raise PrivateKeyExists(self.get_privkey_path())  

    def get_priv_key(self):
        """ Return the crypto object """
        return self.priv_key
    
    def get_pub_key(self):
        """ Return the crypto oject """
        return self.pub_key
            
class KeyRSA(KeyBase):  
    def __init__(self, config):  
        KeyBase.__init__(self, config)   
            
    def generate_keypair(self):
        """ Generate a RSA Key, returning in PEM Format """
         
        # Check if a key exists
        self.has_key()
        
        # RSA Key Generation
        try:
            self.priv_key = RSA.generate(self.conf['keys']['size']) 
            priv_key_pem = self.priv_key.exportKey('PEM')
        except:
            raise GenPrivateKeyError()
        
        try:
            self.pub_key = self.priv_key.publickey()
            pub_key_pem = self.pub_key.exportKey('PEM')
        except:
            raise GenPublicKeyError()
        
        self.save_keypair(priv_key_pem, pub_key_pem)

        print('[+] RSA(%d) Private Key generated at %s' % (self.conf['keys']['size'], self.get_privkey_path()))
        print('[+] RSA(%d) Public Key generated at %s' % (self.conf['keys']['size'], self.get_pubkey_path()))  
        
        return True

    def read_private_key(self): 
        """ Read the private key from file """
        try:
            with open(self.get_privkey_path(), "rb") as priv:
                self.priv_key = RSA.importKey(priv.read())
                priv.close()
                
            return True 
        except:
            raise PrivateKeyReadError('Error reading private key: %s' % self.get_privkey_path())

    def read_public_key(self): 
        """ Read the public key from file """
        try:
            with open(self.get_pubkey_path(), "rb") as pub:
                self.pub_key = RSA.importKey(pub.read())
                pub.close()
                
            return True 
        except:
            raise PrivateKeyReadError('Error reading public key: %s' % self.get_pubkey_path())            

    def get_priv_key_pem(self):
        return self.priv_key.exportKey('PEM')
    
    def get_pub_key_pem(self):
        return self.pub_key.exportKey('PEM')
   
class KeyECC(KeyBase):
    """ Elliptic Curve Cryptography Factory class """
    
    def __init__(self, config):  
        KeyBase.__init__(self, config)            

    def generate_keypair(self):
        """ Generate a ECDSA keypair """       

        # If the issuer has a key, stop a new key generation
        self.has_key()
        
        # Private key generation
        try:
            self.priv_key = SigningKey.generate(curve=NIST256p) 
            priv_key_pem = self.priv_key.to_pem()
        except:
            raise GenPrivateKeyError()
        
        # Public Key name is the hash of the public key
        try:
            self.pub_key = self.priv_key.get_verifying_key()
            pub_key_pem = self.pub_key.to_pem()
        except:
            raise GenPublicKeyError()
        
        # Save the keypair
        self.save_keypair(priv_key_pem, pub_key_pem)
        
        print('[+] ECC(%s) Private Key generated at %s' % (self.conf['keys']['curve'], self.get_privkey_path()))
        print('[+] ECC(%s) Public Key generated at %s' % (self.conf['keys']['curve'], self.get_pubkey_path()))  

    def read_private_key(self): 
        """ Read the private key from files """
        try:
            with open(self.get_privkey_path(), "rb") as priv:
                self.priv_key = SigningKey.from_pem(priv.read())
                priv.close()
                
            return True 
        except:
            raise PrivateKeyReadError('Error reading private key: %s' % self.get_privkey_path())
        
    def read_public_key(self): 
        """ Read the public key from files """
        try:
            with open(self.get_pubkey_path(), "rb") as pub:
                self.pub_key = VerifyingKey.from_pem(pub.read())
                pub.close()
                
            return True 
        except:
            raise PublicKeyReadError('Error reading public key: %s' % self.get_pubkey_path())                               

    def get_priv_key_pem(self):
        return self.priv_key.to_pem()
    
    def get_pub_key_pem(self):
        return self.pub_key.to_pem()
        
