#!/usr/bin/env python3

""" Exception file """


class ECDSAPrivateKeyGenError(Exception):
    def __init__(self):
        self.msg = 'Error during ECDSA private key generation'

    def __str__(self):
        return repr(self.msg)

class ECDSAPublicKeyGenError(Exception):
    def __init__(self):
        self.msg = 'Error during ECDSA public key generation'

    def __str__(self):
        return repr(self.msg)    

class ECDSAHashError(Exception):
    def __init__(self):
        self.msg = 'Error during SHA1 calculation'

    def __str__(self):
        return repr(self.msg)

class ECDSASaveErrorPrivate(Exception):
    def __init__(self):
        self.msg = 'Error saving private key file'

    def __str__(self):
        return repr(self.msg)
    
class ECDSASaveErrorPublic(Exception):
    def __init__(self):
        self.msg = 'Error saving public key file'

    def __str__(self):
        return repr(self.msg)
    
class ECDSAKeyExists(Exception):
    def __init__(self, file):
        self.msg = 'An existing ECDSA key is present for this issuer (%s)' % file

    def __str__(self):
        return repr(self.msg)

