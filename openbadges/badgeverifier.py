#!/usr/bin/env python3

"""
    OpenBadge Verificator.
    
    This program will verify the signature of a SVG badge with a local key or doing a download
    of the key specified in the assertion.
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141130
    Verison:  0.1

"""

import argparse

# Local Imports
from config import profiles
from libopenbadges import VerifyFactory

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-i', '--filein', required=True, help='Specify the input SVG file to verify the signature')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the email of the receptor of the badge')
    parser.add_argument('-p', '--profile', required=True, help='Specify the profile to use')
    parser.add_argument('-lk', '--localkey', action="store_true", help='Verify the badge with local pubkey passed as param otherwise, the key in assertion will be used.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1' )
    args = parser.parse_args()
    
    if args.filein and args.receptor:
         try:
            config = profiles[args.profile]
            
            sf = VerifyFactory(config)
            receptor = args.receptor.encode('utf-8')
            
            if sf.is_svg_signature_valid(args.filein, receptor, local_verification=args.localkey):
                print('[+] The Badge Signature is Correct for the user:', args.receptor)
            else:
                print('[!] Badge signature is incorrect, corrupted or tampered for the user:', args.receptor)
            
         except KeyError:
            print('Profile %s not exist in config.py' % args.profile)
         except VerifierExceptions:
             raise
    else:
        parser.print_help()
