# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

"""A polyvalent display function."""

import os
from subprocess import call

from . import pki

def show(thing):
    """A generic pretty print function.

    It attempts to identify the object passed in parameter and display it
    accordingly.

    Handled objects: None, PKI, Node, dict and filepaths to valid (.ecc).key,
    .csr, .cert, .crl, .p12 files (calls relevant openssl command)
    """

    if thing == None:
        print("~~> None object, probably value not set.")
    elif isinstance(thing, pki.PKI):
        print("~~> Printing PKI object...")
        print(thing)
    elif isinstance(thing, pki.Node):
        print("~~> Printing Node object...")
        print(thing)
    elif isinstance(thing, str) and os.path.isfile(thing):
        cmd  = "{0}".format("openssl")
        # figure out file nature
        if "key" in thing.split("/")[-1].split("."):
            print("~~> Printing key...")
            if not "ecc" in thing.split("/")[-1].split("."):
                cmd += " rsa"
            else:
                cmd += " ecparam -param_enc explicit"
        elif "csr" in thing.split("/")[-1].split("."):
            print("~~> Printing csr...")
            cmd += " req"
        elif "cert" in thing.split("/")[-1].split("."):
            print("~~> Printing cer...")
            cmd += " x509"
        elif "crl" in thing.split("/")[-1].split("."):
            print("~~> Printing crl...")
            cmd += " crl"
        elif "p12" in thing.split("/")[-1].split("."):
            print("~~> Printing pkcs12...")
            cmd  = "cat {0}".format(thing)
            
            print("\t`-> [openssl] " + cmd)
            
            if call(cmd.split()):
                print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")
            return
        else:
            print("\t/!\ [Warning]\t\tUnsupported extension: {0}".format(thing))
            return

        # invariable for key, csr, cert and crl files
        cmd += " -in {0}".format(thing)
        cmd += " -noout"
        cmd += " -text"

        print("\t`-> [openssl] " + cmd)

        if call(cmd.split()):
            print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")
    elif isinstance(thing, dict):
        print("\t`-> [info] " + " : ".join(thing.keys()))
    else:
        print("\t/!\ [Warning]\t\tObject not identified: {0}".format(str(thing)))
