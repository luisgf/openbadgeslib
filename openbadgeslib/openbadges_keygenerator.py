#!/usr/bin/env python3
"""
        OpenBadges Library
         
        Copyright (c) 2014, Luis Gonzalez Fernandez 
        All rights reserved.

        Redistribution and use in source and binary forms, with or without
        modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this
        list of conditions and the following disclaimer. 
        2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.

        THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
        ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
        WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
        DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
        ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
        (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
        LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
        ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
        (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
        SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        The views and conclusions contained in the software and documentation are those
        of the authors and should not be interpreted as representing official policies, 
        either expressed or implied, of the FreeBSD Project.
"""
"""
        KeyPair Generator.
    
        This program will create an RSA/EC key pair for the issuer specified in the config
    
        Author:   Luis Gonzalez Fernandez <luisgf@luisgf.es>
        Date:     20141201
        Version:  0.1
"""

import argparse

# Local Imports
from config import profiles 
from openbadgeslib import KeyFactory
from openbadgeslib.errors import KeyGenExceptions

# Entry Point
def main():
    parser = argparse.ArgumentParser(description='Key Generation Parameters')     
    parser.add_argument('-p', '--profile', required=True, help='Specify the profile to use')
    parser.add_argument('-g', '--genkey', action="store_true", help='Generate a new Key pair. Key type is taken from profile.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1' )
    args = parser.parse_args()
    
    if not args.genkey:
        parser.print_help()
    else:
        """ Check if the profile exists """
        try:
            config = profiles[args.profile]
            print("[!] Generating key pair for issuer '%s'" % config['issuer']['name'])
            
            kf = KeyFactory(config)
            kf.generate_keypair()  
            
        except KeyError:
            print('Profile %s not exist in config.py' % args.profile)
        except KeyGenExceptions:
            raise

if __name__ == '__main__':
    main()
             
  


           

