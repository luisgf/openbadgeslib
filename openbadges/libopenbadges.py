#!/usr/bin/env python3
#description     : Library for dealing with signing of badges
#author          : Luis G.F
#date            : 20141120
#version         : 0.1 

import hashlib
import os
import sys
import time

from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError

# Local imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "./3dparty/")))
import jws.utils

class ECDSAPrivateKeyGenError(Exception):
    pass

class ECDSAPublicKeyGenError(Exception):
    pass

class HashError(Exception):
    pass

class ECDSASaveErrorPrivate(Exception):
    pass
    
class ECDSASaveErrorPublic(Exception):
    pass
    
class ECDSAKeyExists(Exception):
    pass

class ECDSAReadPrivKeyError(Exception):
    pass

class ECDSAReadPubKeyError(Exception):
    pass
    
class KeyFactory():
    """ ECDSA Factory class """
    
    def __init__(self, conf):
        self.private_key = None
        self.public_key = None
        self.issuer = None
        self.private_key_file = conf.keygen['private_key_path']
        self.public_key_file = conf.keygen['public_key_path']

        self.issuer = conf.issuer['name']

    def has_key(self):
        """ Check if a issuer has a private key generated """
       
        key_path = self.private_key_file + sha1_string(self.issuer) + b'.pem'
        
        if os.path.isfile(key_path):
            raise ECDSAKeyExists(key_path)        

    def generate_keypair(self):
        """ Generate a ECDSA keypair """       

        # If the issuer has a key, stop a new key generation
        self.has_key()
        
        # Private key generation
        try:
            self.private_key = SigningKey.generate(curve=NIST256p)            
            self.private_key_file += sha1_string(self.issuer) + b'.pem'
        except:
            raise ECDSAPrivateKeyGenError()
        
        # Public Key name is the hash of the public key
        try:
            self.public_key = self.private_key.get_verifying_key()
            self.public_key_file += sha1_string(self.get_public_pem()) + b'.pem'
        except:
            raise ECDSAPublicKeyGenError()

    def read_private_key(self, private_key_file): 
        """ Read the private key from files """
        try:
            with open(private_key_file, "rb") as priv:
                self.private_key_file = private_key_file
                self.private_key = SigningKey.from_pem(priv.read())
                priv.close()
                
            return True 
        except:
            raise ECDSAReadPrivKeyError('Error reading private key: %s' % self.private_key_file)
            return False
        
    def read_public_key(self, public_key_file): 
        """ Read the public key from files """
        try:
            with open(public_key_file, "rb") as pub:
                self.public_key_file = public_key_file
                self.public_key = VerifyingKey.from_pem(pub.read())
                pub.close()
                
            return True 
        except:
            raise ECDSAReadPubKeyError('Error reading public key: %s' % self.public_key_file)
            return False        
                        
    def save_keypair(self):      
        """ Save keypair to file """        
        try:
            with open(self.private_key_file, "wb") as priv:
                priv.write(self.get_private_pem())
                priv.close()                
        except:
             raise ECDSASaveErrorPrivate()
         
        try:
            with open(self.public_key_file, "wb") as pub:
                pub.write(self.get_public_pem())                    
                pub.close()                
        except:
             raise ECDSASaveErrorPublic() 

    def get_private_pem(self):
        """ Return private key in PEM format """
        return self.private_key.to_pem()
    
    def get_public_pem(self):
        """ Return public key in PEM format """
        return self.public_key.to_pem()    

""" Signer Exceptions """

class BadgeNotFound(Exception):
    pass

class SignerFactory():
    """ JWS Signer Factory """
    
    def __init__(self, conf, badgename, receptor):
        self.conf = conf                              # Access to config.py values                
        self.receptor = receptor                      # Receptor of the badge
        
        try:
            if conf.badges[badgename]:
                self.badge = conf.badges[badgename]
        except KeyError:
            raise BadgeNotFound()
        
    def generate_uid(self):
        """ Generate a UID for a signed badge, Return a str """
        
        return sha1_string(self.conf.issuer['name'] + self.badge['name'] + self.receptor).decode('utf-8')

        
    def generate_assertion(self): 
        """ Generate JWS Assertion """        
        
        # All this data MUST be a Str string in order to be converted to json properly.
        
        recipient_data = dict (
            identity = (b'sha256$' + sha256_string(self.receptor)).decode('utf-8'),
            type = 'email',
            hashed = 'true'
        )                
        
        verify_data = dict(
            type = 'signed',
            url = self.badge['url_key_verif']
        )                
        
        return dict(
                        uid = self.generate_uid(),
                        recipient = recipient_data,
                        image = self.badge['image'],
                        badge = self.badge['json_url'],
                        verify = verify_data,
                        issuedOn = 1416912645 #int(time.time())
                     )  
    
    def generate_openbadge_assertion(self):
        import jws
        
        priv_key = self.conf.keygen['private_key_path'] + sha1_string(self.conf.issuer['name']) + b'.pem'
        
        header = { 'alg': 'ES256' }
        #payload = self.generate_assertion()
        payload = {} # DEBUG

        try:
             sign_key = SigningKey.from_pem(open(priv_key, "rb").read())
        except:
            raise ECDSAReadPrivKeyError()
        
        signature = jws.sign(header, payload, sign_key)
            
        # Hack, save signature to file
        with open("/tmp/signature.txt", "wb") as sig:
                sig.write(signature)                
                sig.close()
        
        assertion = jws.utils.encode(header) + b'.' + jws.utils.encode(payload) + b'.' + jws.utils.to_base64(signature)
        
        # Verificamos en local
        vf = VerifyFactory(self.conf, "public/664840c05c440bb83ae99971a4e244e8fa5cfb0c.pem")
        vf.verify_signature(assertion)
        
        return assertion

class PayloadFormatIncorrect(Exception):
    pass

class VerifyFactory():
    """ JWS Signature Verifier Factory """
    
    def __init__(self, conf, pub_key):
        self.conf = conf                              # Access to config.py values  
        try:
             self.vk = VerifyingKey.from_pem(open(pub_key).read())
        except:
            raise ECDSAReadPubKeyError()
        
    def verify_signature(self, assertion):
        """ Verify the JWS Signature """
        
        print('Verificando Firma...')
        
        try:
            head_encoded, payload_encoded, signature_encoded = assertion.split(b'.')
        except ValueError:
            raise PayloadFormatIncorrect()
        
        signature = jws.utils.base64url_decode(signature_encoded)
        
        try:
            print('Voy a verificar la firma: ')
            print(head_encoded + b'.' + payload_encoded)
            self.vk.verify(signature, head_encoded + b'.' + payload_encoded)
            
            print('FIRMA ECDSA CORRECTA')
        except BadSignatureError:
            print('FIRMA ECDSA INCORRECTA')
       
""" Shared Utils """

def sha1_string(string):
    """ Calculate SHA1 digest of a string """
    try:
        hash = hashlib.new('sha1')
        hash.update(string)
        return hash.hexdigest().encode('utf-8')     # hexdigest() return an 'str' not bytes.
    except:
        raise HashError() 

def sha256_string(string):
    """ Calculate SHA256 digest of a string """
    try:
        hash = hashlib.new('sha256')
        hash.update(string)
        return hash.hexdigest().encode('utf-8')     # hexdigest() return an 'str' not bytes.
    except:
        raise HashError() 
                
if __name__ == '__main__':
    unittest.main()
