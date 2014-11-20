#!/usr/bin/env python3

""" Exception file """


class ECDSAKeyGenError(Exception):
    def __init__(self):
        self.msg = 'Error during ECDSA key generation'

    def __str__(self):
        return repr(self.msg)

class ECDSAHashError(Exception):
    def __init__(self):
        self.msg = 'Error during SHA1 calculation'

    def __str__(self):
        return repr(self.msg)

class ECDSASaveError(Exception):
    def __init__(self):
        self.msg = 'Error saving key file'

    def __str__(self):
        return repr(self.msg)

class ECDSAKeyExists(Exception):
    def __init__(self, file):
        self.msg = 'An existing ECDSA key is present for this issuer (%s)' % file

    def __str__(self):
        return repr(self.msg)

