#!/usr/bin/env python3
#description     : This will create a RSA/EC key pair for a given issuer
#author          : Luis G.F
#date            : 20141127
#version         : 0.3 

import argparse

# Local Imports
import config
from libopenbadges import KeyFactoryRSA, KeyFactoryECC

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Key Generation Parameters')
    parser.add_argument('-gr', '--genrsa', action='store_true', help='Generate a new RSA 2048 Key pair')
    parser.add_argument('-ge', '--genecc', action="store_true", help='Generatte a new ECC NIST256p Key pair')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.3' )
    args = parser.parse_args()
    
    if not args.genrsa and not args.genecc:
        print('You must specify a key type to generate, EC (--genecc) or RSA (--genrsa)')
        parser.print_help()
    else:
        if args.genrsa:
            kf = KeyFactoryRSA(config)  
        else:
            kf = KeyFactoryECC(config)
            
        print("[!] Generating key pair for '%s'..." % config.issuer['name'])
        
        kf.generate_keypair()


           

