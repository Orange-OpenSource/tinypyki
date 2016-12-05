# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

"""Core openssl command and environment generation functions.

This is where all the core commands are built, look at the code if you wish to
get an idea of the options used and improve on them.
"""

import os
import pickle
from subprocess import call

from .macros import *

def env(pki):
    """Generates the environment for a pki instance.

    pki -- a PKI object

    Use this once you are done with creating and populating your PKI instance
    and are contempt with it. This function will create the following:

    working directory -- as defined in pki.path["wdidr"]
    key directory     -- as defined in pki.path[".keys"]
    csr directory     -- as defined in pki.path["csrs"]
    cert drectory     -- as defined in pki.path["certs"]
    crls directory    -- as defined in pki.path["crls"]
    sans file, if any -- as defined in pki.path["sans"]
    index file        -- as defined in pki.path["index"]
    serial file       -- as defined in pki.path["serial"]
    openssl config    -- as defined in pki.path["config.cnf"]
    state file        -- as defined in pki.path["state"]

    Have a look at these files to get an idea of the minimum enabled. There are
    a few directives which are not mandatory in the openssl configuration file,
    while others are required for openssl to operate correctly. For more details
    refer to /etc/ssl/openssl.cnf (or relevant configuration template). For
    automation reasons, the bare minimum is specified in the config files and
    everything revolves around the flexibility allowed by command line options.
    """
    print("Generating environment for {0}...".format(pki.id))
    # Create working directory 
    if not os.path.exists(pki.path["wdir"]):
        os.makedirs(pki.path["wdir"])
    # Create log file
    # if not os.path.isfile(pki.path["log"]):
    #     open(pki.path["log"], "a").close()
    # Create .private directory
    # if not os.path.exists(pki.path[".private"]):
    #     os.makedirs(pki.path[".private"])
    # Create .keys directory
    if not os.path.exists(pki.path[".keys"]):
        os.makedirs(pki.path[".keys"])
    # Create csrs directory
    if not os.path.exists(pki.path["csrs"]):
        os.makedirs(pki.path["csrs"])
    # Create certs directory
    if not os.path.exists(pki.path["certs"]):
        os.makedirs(pki.path["certs"])
    # Create crls directory
    if not os.path.exists(pki.path["crls"]):
        os.makedirs(pki.path["crls"])
    # Create randf file
    # if not os.path.isfile(pki.path["randf"]):
    #     open(pki.path["randf"], "a").close()
    # # Create and initialise serial file
    # if not os.path.isfile(pki.path["serial"]):
    #     with open(pki.path["serial"], "a") as s_hdlr:
    #         s_hdlr.write("02")
    #         s_hdlr.close()
    # Create index file
    if not os.path.isfile(pki.path["index"]):
        open(pki.path["index"], "a").close()
    # Create serial file
    if not os.path.isfile(pki.path["serial"]):
        open(pki.path["serial"], "a").close()
    # Create template config file
    if not os.path.isfile(pki.path["config.cnf"]):
        with open(pki.path["config.cnf"], "a") as c_hdlr:
            template  = "################################################################################\n"
            template += "# CSR DEFAULT CONFIG                                                           #\n"
            template += "################################################################################\n\n"

            template += "[ req ]\n\n"
            template += "distinguished_name = csr_distinguished_name\n"
            template += "string_mask        = utf8only\n\n"

            # template += "# Enable passphrase: uncomment below and corresponding section\n"
            # template += "#attributes                      = req_attributes\n\n"

            template += "################################################################################\n\n"

            template += "[ csr_distinguished_name ]\n\n"

            template += "countryName                     = Country Code (max 2)\n"
            template += "countryName_default             = EL                        # default is Elbonia\n"
            template += "countryName_min                 = 2\n"
            template += "countryName_max                 = 2\n\n"

            template += "stateOrProvinceName             = State (max 128)\n"
            template += "stateOrProvinceName_default     = Mudlands\n"
            template += "stateOrProvinceName_max         = 128\n\n"

            template += "localityName                    = City (max 128)\n"
            template += "localityName_default            = Mudcity\n"
            template += "localityName_max                = 128\n\n"

            template += "0.organizationName              = Company (max 64)\n"
            template += "0.organizationName_default      = Dilbert.Ltd\n"
            template += "0.organizationName_max          = 64\n\n"

            template += "# can set a secondary/extended name\n"
            template += "#1.organizationName             = CompanyBis (max 64)\n"
            template += "#1.organizationName_default     = Engineer.Inc\n"
            template += "#1.organizationName_max         = 64\n\n"

            template += "organizationalUnitName          = Unit (max 64)\n"
            template += "organizationalUnitName_default  = R&D\n"
            template += "organizationalUnitName_max      = 64\n\n"

            template += "commonName                      = default-CN-fqdn/name (max 64)\n"
            template += "commonName_max                  = 64\n\n"

            template += "emailAddress                    = @address (max 128)\n"
            template += "emailAddress_max                = 128\n\n"

            template += "################################################################################\n\n"

            # template += "#[ req_attributes ]\n\n"
            # template += "#\n"
            # template += "#challengePassword              = Passphrase\n"
            # template += "#challengePassword_min          = 4\n"
            # template += "#challengePassword_max          = 20\n\n"

            # template += "################################################################################\n"
            # template += "# CUSTOM CONFIG                                                                #\n"
            # template += "################################################################################\n\n"

            # template += "# remember to edit code accordingly if any\n\n"

            template += "################################################################################\n"
            template += "# CRL DEFAULT CONFIG                                                           #\n"
            template += "################################################################################\n\n"

            template += "[ crl_ext ]\n\n"

            template += "issuerAltName               = issuer:copy\n"
            # template += "authorityKeyIdentifier      = keyid:always\n\n"

            template += "################################################################################\n\n"

            template += "[ ca ]\n\n"

            template += "default_ca                  = default\n\n"

            template += "################################################################################\n\n"

            template += "[ default ]\n\n"

            template += "default_md                  = default\n" 
            template += "crl_extensions              = crl_ext\n"
            template += "database                    = {0}\n\n".format(pki.path["index"])
            template += "serial                    = {0}\n\n".format(pki.path["serial"])
            
            # template += "# WARNING, the database entry will be added at the EOF, don't add anything below, use allocated space above\n"

            c_hdlr.write(template)
            c_hdlr.close()
    # Create state file
    if not os.path.isfile(pki.path["state"]):
        open(pki.path["state"], "a").close()

def save(pki):
    """Save pki state on disk.

    pki -- a PKI object

    Pickle the pki object in the pki.path["state"] file for later reuse.
    """
    print("Saving pki instance {0}...".format(pki.id))
    with open(pki.path["state"], "wb") as p_hdlr:
        pickle.dump(pki, p_hdlr)
        p_hdlr.close()

def key(node, state=True):
    """Generate an RSA key file.

    node  -- a Node object
    state -- boolean, save pki state after creation (default True)

    This function builds the relevant command for creating an RSA key.

    If successfully created, it sets the node's internal status to "csr".

    Since there are limitations in handling .der file formats, the manipulated
    key is in .pem format. See gen.keyform for format conversion.
    """
    cmd  = "{0} genpkey".format(node.pki.path["openssl"])
    cmd += " -algorithm rsa"
    cmd += " -pkeyopt rsa_keygen_bits:{0}".format(node.key_len)
    cmd += " -out {0}/{1}.key.pem".format(node.pki.path[".keys"], node.nid)
    cmd += " -outform pem"

    print("\t`-> [openssl] " + cmd)

    if not call(cmd.split()):
        node.key_path = "{0}/{1}.key.pem".format(node.pki.path[".keys"], node.nid)
        node._status = "csr"
    else:
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

    if state:
      save(node.pki)

def keyform(node, outform):
    """Format conversion of RSA key files.

    node    -- a Node object
    outform -- string, output format, must be in FORMATS

    Typically used for for converting .pem RSA key files to .der.
    
    It assumes inform is pem, swap pem and der if you wish to do the reverse
    operation.  
    """
    if not outform in FORMATS:
        return

    cmd  = "{0} rsa".format(node.pki.path["openssl"])
    cmd += " -in {0}".format(node.key_path)
    cmd += " -inform pem"
    cmd += " -out {0}".format(".".join(node.key_path.split(".")[:-1]) + ".{0}".format(outform))
    cmd += " -outform {0}".format(outform)

    print("\t`-> [openssl] " + cmd)

    if call(cmd.split()):
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def csr(node, state=True, verbose=False):
    """Generate a certificate signing request file.

    node    -- a Node object
    state   -- boolean, save pki state after creation (default True)
    verbose -- boolean, enable verbose option in the openssl command (default False)

    This function builds the relevant command for creating a csr file.
    The relevant keyfile must exist.
    
    If successfully created, it sets the node's internal status to "cert".

    Since there are limitations in handling .der file formats, the manipulated
    csr is in .pem format. See gen.csrform for format conversion.
    """
    # Create sans file if it does not exists :  
    # question: we only need to change sans when adding or modifying a node, this  is used for the csr generation and as such should be performed in csr()
    with open(node.pki.path["sans"], "a") as san_hdlr:
      if node._status == "csr" :
        template  = "[ {0}_ext ]\n\n".format(node.nid)
        template += "basicConstraints       =  critical,CA:{0},pathlen:{1}\n".format("TRUE" if node.ntype == "ca" else "FALSE",node.pathlen)
        #  digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly and decipherOnly
        #  serverAuth             SSL/TLS Web Server Authentication.
        #  clientAuth             SSL/TLS Web Client Authentication.
        #  codeSigning            Code signing.
        #  emailProtection        E-mail Protection (S/MIME).
        #  timeStamping           Trusted Timestamping
        #  msCodeInd              Microsoft Individual Code Signing (authenticode)
        #  msCodeCom              Microsoft Commercial Code Signing (authenticode)
        #  msCTLSign              Microsoft Trust List Signing
        #  msSGC                  Microsoft Server Gated Crypto
        #  msEFS                  Microsoft Encrypted File System
        #  nsSGC  
        # extendedKeyUsage=critical,codeSigning,1.2.3.4          
        template += "keyUsage               =  {0}\n".format("cRLSign,keyCertSign" if node.ntype == "ca" else "nonRepudiation,digitalSignature,keyEncipherment")
        template += "subjectKeyIdentifier   =  hash\n"
        if node.nid != node.issuer:
          template += "issuerAltName          =  issuer:copy\n"
          # template += "authorityKeyIdentifer  =  keyid,issuer\n"
        if node.crl_dps:
          template += "crlDistributionPoints  =  {0}\n".format(",".join(["URI:" + uri for uri in node.crl_dps.lower().replace(" ", "").split(",")]))
          print("working on node: "+ node.subj)
        if node.ocsp_uri:
          template += "authorityInfoAccess  =  OCSP;{0}\n".format(",".join(["URI:" + uri for uri in node.ocsp_uri.lower().replace(" ","").split(",")]))
        if node.san:
          ip_idx = dns_idx = uri_idx = email_idx = 1
          template          += "subjectAltName         =  @{0}_san\n".format(node.nid)
          template          += "\n[ {0}_san ]\n\n".format(node.nid)
          for altname in node.san.lower().replace(" ","").split(","):
            if altname.startswith("ip"):
              template  += "IP.{0:<10} = {1}\n".format(ip_idx, altname.split("=")[-1].strip())
              ip_idx    += 1
            elif altname.startswith("dns"):
              template  += "DNS.{0:<9} = {1}\n".format(dns_idx, altname.split("=")[-1].strip())
              dns_idx   += 1
            elif altname.startswith("email"):
              template  += "email.{0:<7} = {1}\n".format(email_idx, altname.split("=")[-1].strip())
              email_idx += 1
            elif altname.startswith("uri"):
              template  += "URI.{0:<9} = {1}\n".format(uri_idx, altname.split("=")[-1].strip())
              uri_idx   += 1
            else:
              print("\t/!\ [WARNING]\t\tSkipping subject alternative name argument: {0}".format(altname))
        template              += "\n"
        san_hdlr.write(template)
        node.san_id = node.nid + "_ext"
      san_hdlr.close()

    cmd  = "{0} req".format(node.pki.path["openssl"])
    cmd += " -new"
    cmd += " -{0}".format(node.csr_digest)
    cmd += " -key {0}".format(node.key_path)
    cmd += " -keyform pem"
    cmd += " -subj {0}".format(node.subj)
    cmd += " -out {0}/{1}.csr.pem".format(node.pki.path["csrs"], node.nid)
    cmd += " -outform pem"
    cmd += " -config {0}".format(node.pki.path["config.cnf"])
    if verbose:
        cmd += " -verbose"

    print("\t`-> [openssl] " + cmd)

    # Subject might contain white spaces, therefore, ensure the split does not break the command line
    if not call(cmd.split()[:cmd.split().index("-subj")+1] 
                + [" ".join(cmd.split()[cmd.split().index("-subj") + 1 : cmd.split().index("-out")])]
                + cmd.split()[cmd.split().index("-out"):]):
        node.csr_path = "{0}/{1}.csr.pem".format(node.pki.path["csrs"], node.nid)
        node._status = "cert"
    else:
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

    if state:
      save(node.pki)

def csrform(node, outform):
    """Format conversion of csr files.

    node    -- a Node object
    outform -- string, output format, must be in FORMATS

    Typically used for for converting .pem csr files to .der.
    
    It assumes inform is pem, swap pem and der if you wish to do the reverse
    operation.  
    """
    if not outform in FORMATS:
        return

    cmd  = "{0} req".format(node.pki.path["openssl"])
    cmd += " -in {0}".format(node.csr_path)
    cmd += " -inform pem"
    cmd += " -out {0}".format(".".join(node.csr_path.split(".")[:-1]) + ".{0}".format(outform))
    cmd += " -outform {0}".format(outform)

    print("\t`-> [openssl] " + cmd)

    if call(cmd.split()):
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def cert(node, state=True):
    """Generate certificate file.

    node  -- a Node object
    state -- boolean, save pki state after creation (default True)

    This function builds the relevant command for creating a cert file.
    The relevant csr, issuer and PKI files must exist.
    
    If successfully created, it sets the node's internal status to "crl" if it is a "ca", otherwise it sets it to "done".

    Since there are limitations in handling .der file formats, the manipulated
    cert is in .pem format. See gen.certform for format conversion. 
    """
    cmd  = "{0} x509".format(node.pki.path["openssl"])
    cmd += " -req"
    cmd += " -in {0}".format(node.csr_path)
    cmd += " -inform pem"
    if node.nid == node.issuer:
        cmd += " -signkey {0}".format(node.key_path)
        cmd += " -keyform pem"
    else:
        cmd += " -CA {0}".format(node.pki.nodes[node.issuer].cert_path)
        cmd += " -CAform pem"
        cmd += " -CAkey {0}".format(node.pki.nodes[node.issuer].key_path)
        cmd += " -CAkeyform pem"
        # cmd += " -CAserial {0}".format(node.pki.path["serial"])
    cmd += " -set_serial 0x{0}".format(node.pki.serial)
    cmd += " -{0}".format(node.cert_digest)
    cmd += " -days {0}".format(node.life)
    if node.san_id:
        cmd += " -extfile {0}".format(node.pki.path["sans"])
        cmd += " -extensions {0}".format(node.san_id)
    cmd += " -out {0}/{1}.cert.pem".format(node.pki.path["certs"], node.nid)
    cmd += " -outform pem"

    print("\t`-> [openssl] " + cmd)

    if not call(cmd.split()):
        node.cert_path = "{0}/{1}.cert.pem".format(node.pki.path["certs"], node.nid)
        node._status = "crl" if node.ntype == "ca" else "done"
        node.pki.increment()
    else:
        print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

    if state:
      save(node.pki)

def certform(node, outform):
    """Format conversion of cert files.

    node    -- a Node object
    outform -- string, output format, must be in FORMATS

    Typically used for for converting .pem cert files to .der.
    
    It assumes inform is pem, swap pem and der if you wish to do the reverse
    operation.  
    """
    if not outform in FORMATS:
        return

    cmd  = "{0} x509".format(node.pki.path["openssl"])
    cmd += " -in {0}".format(node.cert_path)
    cmd += " -inform pem"
    cmd += " -out {0}".format(".".join(node.cert_path.split(".")[:-1]) + ".{0}".format(outform))
    cmd += " -outform {0}".format(outform)

    print("\t`-> [openssl] " + cmd)

    if call(cmd.split()):
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def crl(node, state=True, verbose=False):
    """Generate certificate revocation list file.

    node    -- a Node object
    state   -- boolean, save pki state after creation (default True)
    verbose -- boolean, enable verbose option in the openssl command (default False)

    This function builds the relevant command for creating crl file.
    
    If successfully created, it sets the node's internal status to "done".

    Since there are limitations in handling .der file formats, the manipulated
    crl is in .pem format. See gen.crlform for format conversion. 
    """
    if node.ntype == "u" or node.pathlen == 0 and node.ntype == "ca":
        node._status = "done"
        print("Node {0} does not need a crl: ntype = {1} pathlen = {2} issuer = {3}".format(node.nid, node.ntype, node.pathlen, node.issuer))
        return

    cmd  = "{0} ca".format(node.pki.path["openssl"])
    cmd += " -gencrl"
    cmd += " -cert {0}".format(node.cert_path)
    cmd += " -keyfile {0}".format(node.key_path)
    cmd += " -crldays {0}".format(node.crl_life)
    cmd += " -out {0}/{1}.crl.pem".format(node.pki.path["crls"], node.nid)
    cmd += " -config {0}".format(node.pki.path["config.cnf"])
    cmd += " -crlexts {0}".format("crl_ext")
    if verbose:
        cmd += " -verbose"

    print("\t`-> [openssl] " + cmd)

    if state and node.crl_path:
        os.rename(node.crl_path, node.crl_path + ".old")
    if not call(cmd.split()):
        node.crl_path = "{0}/{1}.crl.pem".format(node.pki.path["crls"], node.nid)
        node._status = "done"
    else:
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def crlform(node, outform):
    """Format conversion of crl files.

    node    -- a Node object
    outform -- string, output format, must be in FORMATS

    Typically used for for converting .pem crl files to .der. 
    
    It assumes inform is pem, swap pem and der if you wish to do the reverse
    operation.  
    """
    if not outform in FORMATS:
        return
        
    cmd  = "{0} crl".format(node.pki.path["openssl"])
    cmd += " -in {0}".format(node.crl_path)
    cmd += " -inform pem"   
    cmd += " -out {0}".format(".".join(node.crl_path.split(".")[:-1]) + ".{0}".format(outform))
    cmd += " -outform {0}".format(outform)

    print("\t`-> [openssl] " + cmd)

    if call(cmd.split()):
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def pkcs12(node):
    """Generate pkcs12 bundle file.

    node  -- a Node object
    state -- boolean, save pki state after creation (default True)

    This function builds the relevant command for creating a p12 file.
    
    Since the p12 still have a password prompt when handled, a .txt version is
    also built which is the file manipulated through node.p12_path. This is done
    for automation reasons.
    """
    cmd  = "{0} pkcs12".format(node.pki.path["openssl"])
    cmd += " -export"
    cmd += " -password pass:"
    cmd += " -in {0}".format(node.cert_path)
    cmd += " -inkey {0}".format(node.key_path)
    cmd += " -certfile {0}".format(node.cert_path)
    cmd += " -name {0}".format(node.nid)
    cmd += " -macalg sha1"
    cmd += " -out {0}/{1}.p12".format(node.pki.path["certs"], node.nid)

    print("\t`-> [openssl] " + cmd)

    if call(cmd.split()):
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

    cmd  = "{0} pkcs12".format(node.pki.path["openssl"])
    cmd += " -in {0}".format("{0}/{1}.p12".format(node.pki.path["certs"], node.nid))
    cmd += " -nodes"
    cmd += " -password pass:"
    cmd += " -out {0}.txt".format("{0}/{1}.p12".format(node.pki.path["certs"], node.nid))

    print("\t`-> [openssl] " + cmd)

    if not call(cmd.split()):
        node.p12_path = "{0}.txt".format("{0}/{1}.p12".format(node.pki.path["certs"], node.nid))
    else:
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def ecc_key(node, state=True):
    """Generate an ECC key file.

    node  -- a Node object
    state -- boolean, save pki state after creation (default True)

    This function builds the relevant command for creating an ECC key.
    
    Since there are limitations in handling .der file formats, the manipulated
    key is in .pem format.
    """
    # Generate curve parameter file
    cmd  = "{0} ecparam".format(node.pki.path["openssl"]) 
    cmd += " -name {0}".format(node.curve_name)
    cmd += " -genkey"
    cmd += " -out {0}/{1}.ecc.key.pem".format(node.pki.path[".keys"], node.nid)

    print("\t`-> [openssl] " + cmd)

    if not call(cmd.split()):
        node.key_path = "{0}/{1}.ecc.key.pem".format(node.pki.path[".keys"], node.nid)
        node._status = "csr"
    else:
        print("\t/!\ [WARNING]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

    if state:
      save(node.pki)
