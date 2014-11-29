#!/usr/bin/env python3
#description     : This will create a RSA/EC key pair for a given issuer
#author          : Luis G.F
#date            : 20141129
#version         : 0.4

import argparse

# Local Imports
import config
from libopenbadges import KeyFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Key Generation Parameters')
    
    if config.PLEASE_ENABLE_ECC:
        parser.add_argument('-g', '--genkey', choices=["RSA","ECC"], help='Generate a new RSA (2048bits) or ECC(NIST256p) Key pair')
    else:
         parser.add_argument('-g', '--genkey', action="store_const", const="RSA", help='Generate a new RSA Key pair')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.4' )
    args = parser.parse_args()
    
    if not args.genkey:
        parser.print_help()
    else:
        kf = KeyFactory(args.genkey, config)
                
        print("[!] Generating key pair for '%s'..." % config.issuer['name'])
        kf.generate_keypair()  

             
  


           

