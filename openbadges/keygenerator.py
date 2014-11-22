#!/usr/bin/env python3
#description     : This will create a ECDSA key for a given issuer
#author          : Luis G.F
#date            : 20141122
#version         : 0.2 

""" ECDSA Key Generator """

import argparse

# Local Imports
import config
from libopenbadges import KeyFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Key Generation Parameters')
    parser.add_argument('-g', '--genkey', action='store_true', help='Generate a new ECDSA KeyPair')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2' )
    args = parser.parse_args()
    
    if args.genkey:
        kf = KeyFactory(config)  
        print(u"[!] Generating Issuer key for '%s'..." % kf.issuer.decode('UTF-8'))
    
        kf.generate_keypair()
        kf.save_keypair()
    
        print("Private Key Generated: %s" % kf.private_key_file)
        print("Public Key Generated: %s" % kf.public_key_file)
    else:
        parser.print_help()

