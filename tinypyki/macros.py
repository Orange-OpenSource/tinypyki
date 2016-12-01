# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

"""Various macros used accross tinypyki."""

# Node types
NTYPES     = ("ca",  "u")

# File formats
FORMATS    = ("pem", "der")

# Digests
DIGESTS    = ("md5", "sha1", "sha256", "sha384", "sha512")

# Subject creation helper
SUBJECT    = { "country"      : "/C=",
               "state"        : "/ST=",
               "city"         : "/L=",
               "organisation" : "/O=",
               "department"   : "/OU=",
               "email"        : "/emailAddress=",
               "cn"           : "/CN=", }

# Revocation reasons
REASONS    = { "unspecified"          : "unspecified",
               "keycompromise"        : "keyCompromise",
               "cacompromise"         : "CACompromise",
               "affiliationchanged"   : "affiliationChanged",
               "superseded"           : "superseded",
               "cessationofoperation" : "cessationOfOperation",
               "certificatehold"      : "certificateHold",
               "removefromcrl"        : "removeFromCRL" }

# ECC curves: see openssl ecc list_curves
ECC_CURVES = [ "secp112r1",  "secp112r2",  "secp128r1",  "secp128r2",  
               "secp160k1",  "secp160r1",  "secp160r2",  "secp192k1",  
               "secp224k1",  "secp224r1",  "secp256k1",  "secp384r1",  
               "secp521r1",  "prime192v1", "prime192v2", "prime192v3", 
               "prime239v1", "prime239v2", "prime239v3", "prime256v1",
               "sect113r1",  "sect113r2",  "sect131r1",  "sect131r2",  
               "sect163k1",  "sect163r1",  "sect163r2",  "sect193r1",  
               "sect193r2",  "sect233k1",  "sect233r1",  "sect239k1",  
               "sect283k1",  "sect283r1",  "sect409k1",  "sect409r1",  
               "sect571k1",  "sect571r1",  "c2pnb163v1", "c2pnb163v2",
               "c2pnb163v3", "c2pnb176v1", "c2tnb191v1", "c2tnb191v2", 
               "c2tnb191v3", "c2pnb208w1", "c2tnb239v1", "c2tnb239v2", 
               "c2tnb239v3", "c2pnb272w1", "c2pnb304w1", "c2tnb359v1", 
               "c2pnb368w1", "c2tnb431r1", "wap-wsg-idm-ecid-wtls1",
               "wap-wsg-idm-ecid-wtls3",   "wap-wsg-idm-ecid-wtls4",   
               "wap-wsg-idm-ecid-wtls5",   "wap-wsg-idm-ecid-wtls6",   
               "wap-wsg-idm-ecid-wtls7",   "wap-wsg-idm-ecid-wtls8",
               "wap-wsg-idm-ecid-wtls9",   "wap-wsg-idm-ecid-wtls10",  
               "wap-wsg-idm-ecid-wtls11",  "wap-wsg-idm-ecid-wtls12",  
               "Oakley-EC2N-3",            "Oakley-EC2N-4" ]

# A rsa size generator for compliancy check
def SIZES(max_pow=16):
    """A power of two generator.

    max_pow -- maximum power stop condition (default 16)
    """
    for p in range(max_pow):
        yield 2**p
