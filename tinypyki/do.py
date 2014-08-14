# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

"""Core PKI manipulation functions."""

import pickle
import os
from subprocess import call, Popen, PIPE

from .macros import *
from . import gen

def insert(node, pki):
    """Insert a node into a PKI tree.

    node -- a Node object
    pki  -- a pki object

    Use this once you are contempt with the configuration of your node and pki.

    This function solves several dependencies for you:
    node type -- turns self-signed certificates (by default .issuer==.nid, .pathlen==0, .ntype="ca") 
                 to users (.ntype=0, .sign_list=[.nid])
    issuer    -- if the issuer is not inserted in the pki, it prompts you to do so
                 if not present, it adds itself to the issuer's sign_list
    pathlen   -- checks if the issuer can indeed issue a certificate (not self-signed, not a user, not pathlen == 0)
                 updates pathlen accordingly (0 if user, issuer.pathlen - 1 otherwise)
    pki       -- inserts the node in pki.nodes and references the pki through node.pki
    """
    if node.issuer == node.nid and node.pathlen < 1 and node.ntype == "ca":
        node.ntype = "u"
        node.sign_list = [node.nid]

    if node.issuer != node.nid and not node.issuer in pki.nodes:
        print("First create and insert parent node with issuer ID: {0}".format(node.issuer))
        return

    if node.issuer != node.nid and (pki.nodes[node.issuer].ntype == "u" or pki.nodes[node.issuer].pathlen == 0):
        print("Parent node cannot issue a certificate: ntype={0} and pathlen={1}".format(pki.nodes[node.issuer].ntype, pki.nodes[node.issuer].pathlen))
        return

    pki.nodes[node.nid] = node
    node.pathlen        = 0 if node.ntype == "u" else pki.nodes[node.issuer].pathlen - 1 if node.issuer != node.nid else node.pathlen
    node.pki            = pki
    if not node.nid in pki.nodes[node.issuer].sign_list:
        pki.nodes[node.issuer].sign_list.append(node.nid) 

    print("~~> Node {0} updated and inserted".format(node.nid))

def clean(pki):
    """Remove all data on disk related to this pki.

    pki -- a PKI object

    Used for cleanup.
    """
    cmd = "rm -rfI {0}".format(pki.path["wdir"])
    print(cmd)
    call(cmd.split())

def keys(pki):
    """Generate all keys for all nodes in the pki.

    pki -- a PKI object

    For each node in pki.nodes whose status is "key" it generates the keys.
    If a node has a curve_name, it generates a ecc key, otherwise it generates
    an RSA key.
    """
    print("~~> Generating keys for {0}...".format(pki.id))
    for node in pki.nodes.values():
        if node._status == "key":
            if not node.curve_name:
                gen.key(node)
            else:
                gen.ecc_key(node)
        else:
            print("Node {0} [status {1}]: {2}".format(node.nid, node._status, node.key_path))

def csrs(pki):
    """Generate all csrs for all nodes in the pki.

    pki - a PKI object

    For each node in pki.nodes whose status is "csr" it generates the csr.
    """
    print("~~> Generating csrs for {0}...".format(pki.id))
    for node in pki.nodes.values():
        if node._status == "csr":
            gen.csr(node)
        else:
            print("\t`-> [info] Skipping node {0} [status {1}]: {2}".format(node.nid, node._status, node.csr_path))

def certs(pki):
    """Generate all certs for all nodes in the pki.

    pki -- a PKI object

    For each node in pki.nodes whose status is "cert" it generates the cert.
    """
    print("~~> Generating certs for {0}...".format(pki.id))
    for nid in pki.ordered():
        if pki.nodes[nid]._status == "cert":
            gen.cert(pki.nodes[nid])
        else:
            print("\t`-> [info] Skipping node {0} [status {1}]: {2}".format(nid, pki.nodes[nid]._status, pki.nodes[nid].cert_path))

def crls(pki):
    """Generate all crls for all nodes in the pki.

    pki -- a PKI object

    For all "ca" nodes in pki.nodes whose status is "crl" it generates the crl.
    """
    print("~~> Generating crls for {0}...".format(pki.id))
    for node in pki.nodes.values():
        if node._status == "crl":
            gen.crl(node)
        else:
            print("\t`-> [info] Skipping node {0} [status {1}]: {2}".format(node.nid, node._status, node.crl_path))

def p12(pki):
    """Generate all p12 for all nodes in the pki.

    pki -- a PKI object

    For all nodes in pki.nodes whose status is "crl" or "done" it generates the p12.
    """
    print("~~> Generating pkcs12 for {0}...".format(pki.id))
    for node in pki.nodes.values():
        if node._status in ["crl", "done"] and not node.p12_path:
            gen.pkcs12(node)
        else:
            print("\t`-> [info] Skipping node {0} [status {1}]: {2}".format(node.nid, node._status, node.p12_path))

def everything(pki, environment=True, pkcs12=False):
    """Generate all files.

    pki         -- a PKI object
    environment -- boolean, also generate pki environment (default True)
    pkcs12      -- boolean, also generate p12 files (default False)

    An all in one function to create everything.
    Equivalent to do.keys(), do.csrs(), do.certs(), do.crls() and, if enabled,
    gen.env() and do.p12().
    """
    if environment:
        gen.env(pki)
    keys(pki)
    csrs(pki)
    certs(pki)
    crls(pki)
    if pkcs12:
        p12(pki)

def load(pki_path):
    """Load a pki instance.

    pki_path -- path to the pki.path["state"] of the saved instance

    Unpickles a saved pki state.
    """
    print("~~> Loading pki instance from {0}...".format(pki_path))
    if os.path.isfile(pki_path):
        with open(pki_path, "rb") as p_hdlr:
            pki = pickle.load(p_hdlr)
            p_hdlr.close
        return pki
    else:
        return None

def revoke(node, reason=None, including=True):
    """Revoke a node and its subtree.

    node      -- a Node object
    reason    -- string, revocation reason, must be in REASONS (defaults to "unspecified")
    including -- revoke this node too or just the subtree

    Specify a node and a reason, and whether or not to include this node, and
    the whole subtree is revoked with the said reason.

    This function also re-generates the CRL file accordingly. If this node is
    also revoked, it re-generates the CRL of the issuer, otherwise, it
    re-generates the CRL of this node.
    """
    print("~~> Revoking {0}...".format(node.nid))

    # revoke subtree
    for nid in node.subtree(including)[::-1]:
        cmd  = "{0} ca".format(node.pki.path["openssl"])
        cmd += " -revoke {0}".format(node.pki.nodes[nid].cert_path)
        cmd += " -crl_reason {0}".format(REASONS[reason] if reason in REASONS else "unspecified")
        cmd += " -keyfile {0}".format(node.pki.nodes[node.pki.nodes[nid].issuer].key_path)
        cmd += " -cert {0}".format(node.pki.nodes[node.pki.nodes[nid].issuer].cert_path)
        cmd += " -config {0}".format(node.pki.path["config.cnf"])

        print("\t`-> [openssl] " + cmd)

        if call(cmd.split()):
           print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

    # update CRLs accordingly
    gen.crl(node.pki.nodes[node.nid if not including and node.ntype == "ca" else node.issuer])

def verifyenv(pki, create=True):
    """Create or destroy verify environment.

    pki    -- a PKI object
    create -- boolean, create/destroy environment (default=True)
    
    openssl requires a particular environment for verifying certificates.
    This function allows you to create/destroy such an environment.
    Have a look at the code to get an idea of what it does.
    """
    # Remove cert hash links
    if not create:
        call("rm {0}/*.0".format(pki.path["certs"]), shell=True)
        return

    # create hash files
    for nid in pki.nodes:
        cmd  = "{0} x509".format(pki.path["openssl"])
        cmd += " -hash"
        cmd += " -in {0}".format(pki.nodes[nid].cert_path)
        cmd += " -noout"
        print("\t`-> [openssl] " + cmd)
        proc = Popen(cmd.split(), stdout=PIPE)
        # link hash file to cert
        hashed = str(proc.communicate()[0].decode(encoding="utf-8").strip())
        cmd  = "ln -sf {0} {1}/{2}.0".format(pki.nodes[nid].cert_path, pki.path["certs"], hashed)
        if call(cmd.split()):
            print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def verify(node, thing=None):
    """A compound verification function.

    node  -- a Node object
    thing -- string, can be any of "key", "csr", "crl", "ecc", "pkcs12", "cert"
             if it is "cert", ensure the proper environment has been created
             first (see verifyenv). For anything else, it verifies everything
             that can be verified for this node (i.e. all the above if defined)
    """
    if thing in ["key", "csr", "crl", "ecc"]:
        cmd  = "{0}".format(node.pki.path["openssl"])
        cmd += " rsa" if thing == "key" else " req" if thing == "csr" else " ecparam" if thing == "ecc" else " crl -CAfile {0}".format(node.cert_path)
        cmd += " -in {0}".format(node.key_path if thing in ["key", "ecc"] else node.csr_path if thing == "csr" else node.crl_path)
        cmd += " -noout"
        cmd += " -check" if thing in ["key", "ecc"] else " -verify" if thing == "csr" else ""

    elif thing == "pkcs12":
        cmd  = "{0} pkcs12".format(node.pki.path["openssl"])
        # Stored is .txt, skip to .p12 files
        cmd += " -in {0}".format(node.p12_path[:-4])
        cmd += " -info"
        cmd += " -noout"
        cmd += " -password pass:"

    elif thing == "cert":
        # get cert hash
        cmd  = "{0} x509".format(node.pki.path["openssl"])
        cmd += " -hash"
        cmd += " -in {0}".format(node.cert_path)
        cmd += " -noout"
        proc = Popen(cmd.split(), stdout=PIPE)
        cert_hash = str(proc.communicate()[0].decode(encoding="utf-8").strip())
        # verify
        cmd  = "{0} verify".format(node.pki.path["openssl"])
        cmd += " -CApath {0}".format(node.pki.path["certs"])
        cmd += " {0}/{1}.0".format(node.pki.path["certs"], cert_hash)

    else:
        if node.key_path:
            if not node.curve_name:
                verify(node, "key")
            else:
                verify(node, "ecc")
        if node.csr_path:
            verify(node, "csr")
        if node.cert_path:
            verify(node, "cert")
        if node.crl_path:
            verify(node, "crl")
        if node.p12_path:
            verify(node, "pkcs12")
        return 

    print("\t`-> [openssl] " + cmd)

    if call(cmd, shell=True):
        print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")

def verify_all(pki):
    """A verification function for the whole pki.

    pki -- a PKI object

    Verifies everything that can be verified for all nodes inserted in the pki.
    """
    print("~~> Verifying everything in PKI: {0}".format(pki.id))
    for node in pki.nodes.values():
        if node.key_path:
            print("\t`-> Verifying key for: {0}".format(node.nid))
            if not node.curve_name:
                verify(node, "key")
            else:
                verify(node, "ecc")
        if node.csr_path:
            print("\t`-> Verifying csr for: {0}".format(node.nid))
            verify(node, "csr")
        if node.cert_path:
            print("\t`-> Verifying cert for: {0}".format(node.nid))
            verify(node, "cert")
        if node.crl_path:
            print("\t`-> Verifying crl for: {0}".format(node.nid))
            verify(node, "crl")
        if node.p12_path:
            print("\t`-> Verifying p12 for: {0}".format(node.nid))
            verify(node, "pkcs12")

def renew_crl(node, life=None, state=True, verbose=False):
    """Renew a crl. 

    node    -- a Node object
    life    -- the new validity duration in days, must be 1<=life<=node.life
    state   -- boolean, save pki state after creation (default True)
    verbose -- boolean, enable verbose option in the openssl command (default False)

    Re-create this node's CRL.
    """
    node.crl_life = min(int(life), node.life) if life and int(life) >= 1 else node.life
    gen.crl(node, state, verbose)

def renew_branch(node, reason="unspecified", including=False):
    """Renew a whole subtree.

    node      -- a Node object
    reason    -- string, revocation reason (default "unspecified"), must be in REASONS
    including -- boolean, include this node or not in the renewal process (default False)

    First, the whole subtree (including this node or not) is revoked for the
    specified reason, then the state of the nodes is set to "key" and then
    the whole subtree is generated anew. If nodes already had a p12 created,
    those too will be automatically re-created.
    """
    # Revoke whole branch
    revoke(node, reason, including)
    # Renew whole branch
    for nid in node.subtree(including):
        node.pki.nodes[nid]._status = "key"
    keys(node.pki)
    csrs(node.pki)
    certs(node.pki)
    crls(node.pki)
    if node.p12_path:
        p12(node.pki)

def keystore(node, format):
    """Generate a keystore.

    node   -- a Node object
    format -- string, the format of the keystore, must be one of "p12", "pkcs12", "cert", "cert", "crt", "pem"

    Creates a keystore of the specified format (p12 or .cert.pem).
    """
    if format in ["p12", "pkcs12"]:
        cmd  = "cat"
        cmd += " {0}".format(node.key_path)
        for nid in node.pki.trust_chain(node.nid):
            cmd += " {0}".format(node.pki.nodes[nid].cert_path)
        cmd += " > {0}/{1}.keystore".format(node.pki.path["certs"], node.nid)
        print("\t`-> [info] " + cmd)
        if call(cmd, shell=True):
            print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")
        cmd  = "{0}".format(node.pki.path["openssl"])
        cmd += " pkcs12"
        cmd += " -export"
        cmd += " -password pass:"
        cmd += " -name {0}".format(node.nid)
        cmd += " -macalg sha1"
        cmd += " -in {0}/{1}.keystore".format(node.pki.path["certs"], node.nid)
        cmd += " -out {0}/{1}.keystore.p12".format(node.pki.path["certs"], node.nid)
        print("\t`-> [openssl] " + cmd)
        if call(cmd.split()):
            print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")
    elif format in ["cert", "cer", "crt", "pem"]:
        cmd  = "cat"
        for nid in node.pki.trust_chain(node.nid):
            cmd += " {0}".format(node.pki.nodes[nid].cert_path)
        cmd += " >> {0}/{1}.keystore.cert.pem".format(node.pki.path["certs"], node.nid)
        print("\t`-> [info] " + cmd)
        if call(cmd, shell=True):
            print("\t/!\ [Warning]\t\tWell, clearly something went wrong when calling, investigate the error message above.")
    else:
        print("\t/!\ [info]\t\tFormat currently not supported: {0}".format(str(format)))
        