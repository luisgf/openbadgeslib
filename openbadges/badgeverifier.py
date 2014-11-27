#!/usr/bin/env python3
#description     : This program will verify the signature of a SVG file
#author          : Luis G.F
#date            : 20141127
#version         : 0.1 


import argparse

# Local Imports
import config
from libopenbadges import VerifyFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-i', '--filein', required=True, help='Specify the input SVG file to verify the signature')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1' )
    args = parser.parse_args()
    
    if args.filein:
        sf = VerifyFactory(config)
        
        if sf.is_svg_signature_valid(args.filein):
            print('[+] The Badge Signature is Correct!')
        else:
            print('[!] Badge signature is incorrect, corrupted or tampered.')
    else:
        parser.print_help()
