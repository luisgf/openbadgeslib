#!/usr/bin/env python3
"""
        Copyright (c) 2014, Luis Gonzalez Fernandez 
        All rights reserved.

        Redistribution and use in source and binary forms, with or without
        modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this
        list of conditions and the following disclaimer. 
        2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.

        THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
        ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
        WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
        DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
        ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
        (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
        LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
        ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
        (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
        SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        The views and conclusions contained in the software and documentation are those
        of the authors and should not be interpreted as representing official policies, 
        either expressed or implied, of the FreeBSD Project.
"""
"""
        OpenBadges Signer.
    
        This programs will generate an output file with a badge and an assertion embedded
    
        Author:   Luis Gonzalez Fernandez <luisgf@luisgf.es>
        Date:     20141201
        Version:  0.1
"""

import argparse

# Local Imports
from config import profiles 
from openbadgeslib import SignerFactory
from openbadgeslib.errors import LibOpenBadgesException, SignerExceptions, BadgeNotFound

# Entry Point
def main():
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')    
    parser.add_argument('-o', '--output', required=True, help='Specify the output directory to save the badge.')
    parser.add_argument('-p', '--profile', required=True, help='Specify the profile to use')
    parser.add_argument('-e', '--evidence', help='Set an url to the user evidence')
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
            sf = SignerFactory(config, args.badge, args.receptor, evidence=args.evidence, debug_enabled=args.debug)  
            print("[!] Generating signature for badge '%s'..." % args.badge)        
            
            # Output file...
            badgeout = sf.generate_output_filename(args.output, args.receptor)
            
            if sf.sign_svg_file(badgeout):
                print('[+] Badge Signed succesfully at: ', badgeout)
            else:
                print('[-] An error has occurred during signing the badge.')
        
        except BadgeNotFound:
            print('%s is not defined or not attached as badge to this profile.' % args.badge)
        except SignerExceptions:
            raise
        except LibOpenBadgesException:
            raise

    else:
        parser.print_help()


if __name__ == '__main__':
    main()