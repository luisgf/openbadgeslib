#!/usr/bin/env python3
#description     : This program will verify the signature of a SVG file
#author          : Luis G.F
#date            : 20141128
#version         : 0.1 


import argparse

# Local Imports
import config
from libopenbadges import VerifyFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-i', '--filein', required=True, help='Specify the input SVG file to verify the signature')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the email of the receptor of the badge')
    parser.add_argument('-lk', '--localkey', help='Verify the badge with local pubkey passed as param otherwise, the key in assertion will be used.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1' )
    args = parser.parse_args()
    
    if args.filein and args.receptor:
        if args.localkey:
            sf = VerifyFactory(config, args.localkey)
        else:
            sf = VerifyFactory(config)
                
        receptor = args.receptor.encode('utf-8')
            
        if sf.is_svg_signature_valid(args.filein, receptor):
            print('[+] The Badge Signature is Correct for the user:', args.receptor)
        else:
            print('[!] Badge signature is incorrect, corrupted or tampered for the user:', args.receptor)
    else:
        parser.print_help()
