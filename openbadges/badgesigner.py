#!/usr/bin/env python3
#description     : This program will sign a badge with a jws signature
#author          : Luis G.F
#date            : 20141124
#version         : 0.2 

""" ECDSA Key Generator """

import argparse

# Local Imports
import config
from libopenbadges import SignerFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')
    parser.add_argument('-i', '--filein', required=True, help='Specify the input SVG file to sign')
    parser.add_argument('-o', '--fileout', required=True, help='Specify the output SVG file that will be signed')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2' )
    args = parser.parse_args()
    
    if args.badge:
        sf = SignerFactory(config, args.badge, args.receptor.encode('utf-8'))  
        print("[!] Generating signature for badge '%s'..." % args.badge)        
        assertion = sf.generate_openbadge_assertion()
        
        if sf.sign_svg_file(args.filein, args.fileout, assertion):
            print('[+] Badge Signed succesfully at: ', args.fileout)

    else:
        parser.print_help()

