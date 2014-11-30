#!/usr/bin/env python3
#description     : This program will sign a badge with a jws signature
#author          : Luis G.F
#date            : 20141129
#version         : 0.3

""" ECDSA Key Generator """

import argparse

# Local Imports
from config import profiles
from libopenbadges import SignerFactory, log, BadgeNotFound

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')    
    parser.add_argument('-o', '--output', required=True, help='Specify the output directory to save the badge.')
    parser.add_argument('-p', '--profile', required=True, help='Specify the profile to use')
    parser.add_argument('-d', '--debug', action="store_true", help='Show debug messages in runtime.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.3' )
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
            
            assertion = sf.generate_openbadge_assertion()
            
            badgein = sf.get_badge_local_path()
            badgeout = sf.generate_output_filename(badgein, args.output, args.receptor)
            
            if sf.sign_svg_file(badgein, badgeout, assertion):
                log(config, 'Badge %s for receptor %s signed succesfully at %s' % (args.badge, args.receptor, badgeout))
                print('[+] Badge Signed succesfully at: ', badgeout)
            else:
                log('Badge %s for receptor %s signed failed.' % (args.badge, args.receptort))
        
        except BadgeNotFound:
            print('%s is not defined or not attached as badge to this profile.' % args.badge)

    else:
        parser.print_help()

