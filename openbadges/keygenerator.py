#!/usr/bin/env python3

"""
    OpenBadge KeyPair Generator.
    
    This program will create an RSA/EC key pair for the issuer specified in the config
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141130
    Verison:  0.1

"""

import argparse

# Local Imports
from config import profiles 
from libopenbadges import KeyFactory

# Entry Point
if __name__ == '__main__':
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
            

             
  


           

