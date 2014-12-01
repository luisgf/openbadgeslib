#!/usr/bin/env python3

"""
    Lib OpenBadges. Object Modeling
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141201
    Verison:  0.2
    
    _Future_Version_
    
    https://github.com/openbadges/openbadges-specification/blob/master/Assertion/latest.md

"""
import sys, os
from urllib.parse import urlparse


# Local imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "./3dparty/")))
import jws.utils

from errors import LibOpenBadgesException

""" Object creation exception """
class WrongUrl(LibOpenBadgesException):
    pass

class WrongDateTime(LibOpenBadgesException):
    pass

class OpenBadge():
    def __init__(self):
        self.uid = None
        self.recipient = Identity()
        self.badge = Badge()
        self.verify = Verification()
        self.issuedon = DateTime()
        self.image = Url()
        self.evidence = Url()
        self.expires = DateTime()

class Url(OpenBadge):
    """ Check if a url is valid, raise error otherwise """
    def __init__(self, url_in):                
        url = urlparse(url_in)         

        if url.scheme != 'https':
            print('[!] Warning! Using insecure URL:', url_in)
        
        if not url.hostname:
            raise WrongUrl('No hostname provided in URL:', url_in)
        
        self.url_parsed = url
        self.url_in = url_in

    def __str__(self):
        return self.url_in
    
    def __bytes__(self):
        return self.url_in.encode('utf-8')

class JsonUrl(Url):
    """ Url that point to a json file """
    def __init__(self, url_in):
        Url.__init__(self, url_in)
        if not self.url_parsed.path.endswith('.json'):
            raise WrongUrl('URL not point to a JSON file:', url_in)

class Email(OpenBadge):
    """ Class that's represent an email address """
    def __init__(self, email_addr):
        from email import utils
        self.email = utils.parseaddr(email_addr)
        
    def __str__(self):
        return self.email[1]
    
    def __bytes__(self):
        return self.email[1].encode('utf-8')
        

class DateTime(OpenBadge):
    def __init__(self):
        self.datetime = None
    
    def now(self):        
        """ Return the current date in UNIX timestamp format """
        
        from time import time
        return int(time()) 
    
    def show(self, ts):
        """ Return a ISO 8601 Date format """        
        from datetime import date
        try:
            date_time = date.fromtimestamp(ts)        
            return date_time.isoformat()
        except:
            raise WrongDateTime()

class Verification(OpenBadge):
    def __init__(self):
        self.type_verif = None
        self.url = Url()

class Badge(OpenBadge):
    def __init__(self):
        self.name = None
        self.description = None
        self.image = Url()
        self.criteria = Url()
        self.issuer_url = JsonUrl()
        self.alignment = list()
        self.tags = list()

class Identity(OpenBadge):
    """ Identify Class, Actually only support Email """
    def __init__(self, email_addr, salt=None):
        self.identity = None
        self.type_id = "email"
        self.hashed = None
        self.salt = salt

class Issuer(OpenBadge):
    def __init__(self):
        self.name = None
        self.url = Url()
        self.description = None
        self.image = Url()
        self.email = None
        self.revocation = JsonUrl()

class Alignment(OpenBadge):
    def __init__(self):
        self.name = None
        self.url = Url()
        self.description = None
       
    