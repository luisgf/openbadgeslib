#!/usr/bin/env python3

"""
    OpenBadge Signer.
    
    This programs will generate an output file with a badge and an assertion embedded
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141201
    Verison:  0.1

"""
import argparse

# Local Imports
from config import profiles
from libopenbadges import SignerFactory
from errors import BadgeNotFound

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')    
    parser.add_argument('-o', '--output', required=True, help='Specify the output directory to save the badge.')
    parser.add_argument('-p', '--profile', required=True, help='Specify the profile to use')
    parser.add_argument('-d', '--debug', action="store_true", help='Show debug messages in runtime.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1' )
    args = parser.parse_args()
    
    if args.badge:
         # Check if the profile exists
        try:
            config = profiles[args.profile]
        except KeyError:
            print('Profile %s not exist in config.py' % args.profile)
            
        try:
            sf = SignerFactory(config, args.badge, args.receptor.encode('utf-8'), debug_enabled=args.debug)  
            print("[!] Generating signature for badge '%s'..." % args.badge)        
            
            # Output file...
            badgeout = sf.generate_output_filename(args.output, args.receptor)
            
            if sf.sign_svg_file(badgeout):
                print('[+] Badge Signed succesfully at: ', badgeout)
            else:
                print('[-] An error has occurred during signing the badge.')
        
        except BadgeNotFound:
            print('%s is not defined or not attached as badge to this profile.' % args.badge)

    else:
        parser.print_help()

