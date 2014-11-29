#!/usr/bin/env python3
#description     : This program will sign a badge with a jws signature
#author          : Luis G.F
#date            : 20141124
#version         : 0.2 

""" ECDSA Key Generator """

import argparse

# Local Imports
import config
from libopenbadges import SignerFactory, log

# Entry Point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')    
    parser.add_argument('-o', '--output', required=True, help='Specify the output directory to save the badge.')
    parser.add_argument('-d', '--debug', action="store_true", help='Show debug messages in runtime.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2' )
    args = parser.parse_args()
    
    if args.badge:
        sf = SignerFactory(config.USE_CRYPTO, config, args.badge, args.receptor.encode('utf-8'), debug_enabled=args.debug)  
        print("[!] Generating signature for badge '%s'..." % args.badge)        
        
        assertion = sf.generate_openbadge_assertion()
        
        badgein = config.badges[args.badge]['local_badge_path']
        badgeout = sf.generate_output_filename(badgein, args.output, args.receptor)
        
        if sf.sign_svg_file(badgein, badgeout, assertion):
            log('Badge %s for receptor %s signed succesfully at %s' % (args.badge, args.receptor, badgeout))
            print('[+] Badge Signed succesfully at: ', badgeout)
        else:
            log('Badge %s for receptor %s signed failed.' % (args.badge, args.receptort))

    else:
        parser.print_help()

