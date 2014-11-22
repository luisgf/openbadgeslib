#!/usr/bin/env python3

""" Issuer Configuration """
issuer = dict(
    name = 'Luis G.F Badge Issuer',
    image = 'https://openbadges.luisgf.es/issuer/logo.png',
    url = 'https://www.luisgf.es',
    email = 'openbadges@luisgf.es',
    revocationList = 'https://openbadges.luisgf.es/issuer/revocation.json'
 )

""" Badge Catalog, You can add more creating dict() at the end """
badges = [
    dict(
        name = 'Badge Test',
        description = 'A badge test example',
        image = 'https://openbadges.luisgf.es/issuer/badges/image.png',
        criteria = 'https://openbadges.luisgf.es/issuer/criteria.html',
        issuer = 'https://openbadges.luisgf.es/issuer/organization.json',
        alignment = ''
    )
]

""" KeyGenerator Configuration """
keygen = dict(   
    private_key_path = '/home/luisgf/sources/openbadges/openbadges/private/',
    public_key_path = '/home/luisgf/sources/openbadges/openbadges/public/',
    url_verif = 'https://openbadges.luisgf.es',
    url_path_keys = '/issuer/pubkeys/'
)

