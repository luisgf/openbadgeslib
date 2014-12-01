OpenBadges Lib:
===============


This is a library that's deal with the problem of key creation, signing and verifiy of openbadges
in SVG format.


<<<<<<< local
La creación de un perfil se realiza añadiendo una entrada al diccionario "profiles", cuya clave
será el nombre del mismo y la cual será la referencia a emplear cuando el programa solicite un perfil.

Dicha entrada debe a su vez crear otro diccionario con 4 claves:

issuer:    Especifica la información del emisor del badge. 
badges:    Lista con los diferentes badges que gestionará este perfil.
keys:      Especifica la ruta hacia las claves pública y privada, así como su tipo y su tamaño.
           Es aqui donde podemos especificar que el programa use o no criptografia ECC.        
signedlog: Fichero de log donde se registrarán las firmas de badges. Guardalo en un lugar seguro!

El fichero por defecto config.py viene con una muestra de 2 perfiles distintos, uno que emplea cifrado
ECC y otro que emplea cifrado RSA.


Generación de Claves:
=====================

La primera vez que instalemos el programa debemos generar un par de claves que se usarán durante
el proceso de firma y verificación de badges. La clave privada debe guardarse en un sitio seguro
así como la clave pública debe exponerse libremente para que los demás puedan verificar nuestros badges.

Para generar un par de claves usaremos la herramienta "keygenerator.py", cuya salida ejecutada con el
parámetro -h es la siguiente.

    $ ./keygenerator.py -h
    usage: keygenerator.py [-h] -p PROFILE [-g] [-v]

    Key Generation Parameters

    optional arguments:
    -h, --help            show this help message and exit
    -p PROFILE, --profile PROFILE
                            Specify the profile to use
    -g, --genkey          Generate a new Key pair. Key type is taken from
                            profile.
    -v, --version         show program's version number and exit

    
Licencia de componentes:
========================

python ecdsa: MIT
pycrypto: varias...
jws: MIT



<EN CONSTRUCCION>
=======
>>>>>>> other
