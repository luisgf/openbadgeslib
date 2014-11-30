#!/usr/bin/env python3
#description     : This will create a RSA/EC key pair for a given issuer
#author          : Luis G.F
#date            : 20141129
#version         : 0.5

import argparse

# Local Imports
from config import profiles 
from libopenbadges import KeyFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Key Generation Parameters')     
    parser.add_argument('-p', '--profile', required=True, help='Specify the profile to use')
    parser.add_argument('-g', '--genkey', action="store_true", help='Generate a new Key pair. Key type is taken from profile.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.5' )
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
            

             
  


           

