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
        OpenBadges Verifier
    
        This program will verify the signature of a SVG badge with a local key or doing a download
        of the key specified in the assertion.
    
        Author:   Luis Gonzalez Fernandez <luisgf@luisgf.es>
        Date:     20141201
        Version:  0.1
"""

import argparse

from config import profiles 
from openbadgeslib.verifier import VerifyFactory
from openbadgeslib.errors import LibOpenBadgesException, VerifierExceptions


# Entry Point
def main():
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
            receptor = args.receptor
            
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

if __name__ == '__main__':
    main()
