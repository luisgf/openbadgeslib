#!/usr/bin/env python3
#description     : This will create a ECDSA key for a given issuer
#author          : Luis G.F
#date            : 20141120
#version         : 0.1 

""" ECDSA Key Generator """

import argparse
from libopenbadges import KeyFactory

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Key Generation Params')
    parser.add_argument('-i', '--issuer', required=True, help='Set the issuer for the key generation')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')

    args = parser.parse_args()

    kf = KeyFactory(args.issuer)   
    kf.generate_keypair()
    kf.save_keypair()
    
    print("Private Key Generated: %s" % kf.private_key_file)
    print("Public Key Generated: %s" % kf.public_key_file)

