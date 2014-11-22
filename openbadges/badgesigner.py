#!/usr/bin/env python3
#description     : This program will sign a badge with a jws signature
#author          : Luis G.F
#date            : 20141122
#version         : 0.2 

""" ECDSA Key Generator """

import argparse

# Local Imports
import config
from libopenbadges import SignerFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-b', '--badge', required=True, type=int, help='Specify the badge id for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge' )
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2' )
    args = parser.parse_args()
    
    if args.badge:
        sf = SignerFactory(config, args.receptor)  
        print(u"[!] Generating signature for badge '%d'..." % args.badge)
        
        signature = sf.generate_jws_signature(args.badge)
        
        print(u"Signature: %s" % signature)

    else:
        parser.print_help()

