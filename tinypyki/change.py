# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

"""Functions to be used when manipulating classes defined in pki.py.

These functions are designed to be used on nodes to set various attributes
before inserting them into a pki instance, not once they are inserted.

Inserting a node solves quite a few dependencies for you and these functions do
not handle the consequences of a change, therefore you will need to fix those
manually.
"""

import os

from .macros import *

def status(node, status=None, clean=True):
    """Manually set a node's status.

    status -- status string, must be in ["key", "csr", "cert", "crl", "done"] (default "key")
    clean  -- boolean, remove the related files if any (default True)

    This function sets the ._status attribute of a node, cleares relevant
    .*_path attributes, after (if clean==True) removing the files.

    Example: status(node, "csr", clean=True) with node._status == "done"
    Result:  node._status == "csr", node.cert_path == node.crl_path == None and
             relevant files are removed.

    Node status and explanations:

    ._status == "key"  -- the key will be generated next, nothing else exists
    ._status == "csr"  -- the csr will be generated next, only the keyfile exists
    ._status == "cert" -- the cert will be generated next, only the key and csr exist
    ._status == "crl"  -- the crl will be generated next, only the key, csr and cert exist
    ._status == "done" -- all the files have been generated

    When reverting a state, ensure that nodes that depend are also updated
    accordingly. When pushing a state forward, ensure the proper steps have been
    taken to generate the corresponding files if the node is inserted.

    This method was originally used to reset a node for tests.
    """
    # set node status
    node._status = status if status in ["key", "csr", "cert", "crl", "done"] else "key"
    # clear paths if required
    if clean and node._status in ["key"]                       and os.path.isfile(str(node.key_path)) : os.remove(node.key_path)
    if clean and node._status in ["key", "csr"]                and os.path.isfile(str(node.csr_path)) : os.remove(node.csr_path)
    if clean and node._status in ["key", "csr", "cert"]        and os.path.isfile(str(node.cert_path)): os.remove(node.cert_path)
    if clean and node._status in ["key", "csr", "cert"]        and os.path.isfile(str(node.p12_path)) : os.remove(node.p12_path)
    if clean and node._status in ["key", "csr", "cert", "crl"] and os.path.isfile(str(node.crl_path)) : os.remove(node.crl_path)
    # clear path references
    node.key_path  = None if node._status in ["key"]                       else node.key_path
    node.csr_path  = None if node._status in ["key", "csr"]                else node.csr_path
    node.cert_path = None if node._status in ["key", "csr", "cert"]        else node.cert_path
    node.p12_path  = None if node._status in ["key", "csr", "cert"]        else node.p12_path
    node.crl_path  = None if node._status in ["key", "csr", "cert", "crl"] else node.crl_path

def nid(node, nid=None):
    """Change a node's unique identifier.

    node -- a Node object
    nid  -- unique string id (default None, leaves the node unchanged)

    Use this function before inserting a node to a pki instance, otherwise, you
    need to fix all the dependencies: issuer's sign_list, pki's nodes dictionary,
    the nodes which have this node as their issuer.
    """
    node.nid = nid if nid else node.nid

def ntype(node, ntype="ca"):
    """Change a node's type.

    node  -- a Node object
    ntype -- node type string (default="ca"), must be in NTYPES

    Use this function before inserting a node to a pki instance, otherwise, you
    need to fix all the dependencies, from issuer to affected subtree.
    """
    node.ntype = ntype if ntype in NTYPES else node.ntype
    if node.ntype == "u":
        node.sign_list = []

def issuer(node, issuer=None):
    """Change a node's issuer.

    node   -- a Node object
    issuer -- issuer's string nid (default=None, leaves the node unchanged)

    Use this function before inserting a node to a pki instance, otherwise, you
    need to fix all the dependencies, from issuer to affected subtree.
    """
    node.issuer = issuer if issuer else node.issuer

def life(node, life=1):
    """Change a node's life.

    node -- a Node object
    life -- integer, certificate validity in days, must be >= 1

    Use this function before generating the key, csr, cert and crl files.
    """
    node.life = int(life) if life and int(life) >= 1 else node.life

def keysize(node, size=None):
    """Change a node's rsa key size.

    node -- a Node object
    size -- size in bits, must be in SIZES

    Use this function before generating the key, csr, cert and crl files.
    """
    g = SIZES()
    node.key_len = size if size in g else node.key_len

def csrdigest(node, digest="sha1"):
    """Change the digest algorith used for signing the node's csr file.

    node   -- a Node object
    digest -- string, algorithm (default "sha1"), must be in DIGESTS

    Use this function before generating the key, csr, cert and crl files.
    """
    node.csr_digest = digest.lower()  if digest.lower() in DIGESTS else node.csr_digest

def certdigest(node, digest="sha1"):
    """Change the digest algorith used for signing the node's cert file.

    node   -- a Node object
    digest -- string, algorithm (default "sha1"), must be in DIGESTS

    Use this function before generating the key, csr, cert and crl files.
    """
    node.cert_digest = digest.lower() if digest.lower() in DIGESTS else node.cert_digest

def crldigest(node, digest="sha1"):
    """Change the digest algorith used for signing the node's crl file.

    node   -- a Node object
    digest -- string, algorithm (default "sha1"), must be in DIGESTS

    Use this function before generating the key, csr, cert and crl files.
    """
    node.crl_digest = digest.lower()  if digest.lower() in DIGESTS else node.crl_digest

def crllife(node, life=1):
    """Change a node's CRL life.

    node -- a Node object
    life -- integer, crl validity in days, must be 1 <= .crl_life <= .life

    Use this function before generating the key, csr, cert and crl files.
    """
    node.crl_life = int(life) if 1<= int(life) <= node.life else node.crl_life

def crldps(node, crl_dps=None):
    """Change a node's CRL DPS URI.

    node -- a Node object
    crl_dps -- string, URI (including the http:// or https:// prefix ) of the CRL distributions points; the string may contain multiple URI separated by commas

    Use this function before generating the csr, cert and crl files.
    """
    node.crl_dps = crl_dps.lower() if crl_dps else None
    
def ocspuri(node, ocsp_uri=None):
    """Change a node's OCSP URI.

    node -- a Node object
    ocsp_uri -- string, URI (including the http:// or https:// prefix ) of the OCSP server; the string may contain multiple URI separated by commas

    Use this function before generating the csr, cert and crl files.
    """
    node.ocsp_uri = ocsp_uri.lower() if ocsp_uri else None
    
def subj(node, country=None, state=None, city=None, organisation=None, department=None, cn="dilbert.com", email=None):
    """Change a node's subject.

    node         -- a Node object
    country      -- country code string (e.g. US, UK, DE, FR...), 
                    only first 2 characters are taken into account 
                    (default None, ignored)
    state        -- region/state/department string (default None, ignored)
    city         -- city name string (default None, ignored)
    organisation -- organisation/institution/company string (default None, ignored)
    department   -- department/unit/team string within the organisation (default None, ignored)
    cn           -- canonical name of the certificate user (mandatory, default "dilbert.com")
    email        -- e-mail address (default None, ignored)

    Use this function before generating the key, csr, cert and crl files.
    """
    node.subj  = (SUBJECT["country"]      + country[:2])  if country      else "" 
    node.subj += (SUBJECT["state"]        + state)        if state        else "" 
    node.subj += (SUBJECT["city"]         + city)         if city         else ""
    node.subj += (SUBJECT["organisation"] + organisation) if organisation else ""
    node.subj += (SUBJECT["department"]   + department)   if department   else ""
    node.subj += (SUBJECT["email"]        + email)        if email        else ""
    node.subj += (SUBJECT["cn"]           + cn)

def san(node, altname):
    """Change a node's subject alternative name.

    node    -- a Node object
    altname -- a string of comma separated alternative names prefixed with ip=, dns=, uri= or email=

    Example: san(node, "ip=10.0.0.10, dns=dilbert.com, uri=http://dilbert.com/san.txt, email=pointy_haired_boss@dilbert.com")
    
    Use this function before generating the key, csr, cert and crl files.
    """
    if altname and isinstance(altname, str):
        node.san = ",".join([an for an in altname.lower().replace(" ", "").split() if an.startswith("ip=") or an.startswith("dns=") or an.startswith("uri=") or an.startswith("email=") ])

def curve(node, name):
    """Change a node's curve.

    node -- a Node object
    name -- curve string name, must be in ECC_CURVES
    
    Use this function before generating the key, csr, cert and crl files.
    """
    node.curve_name = name if name in ECC_CURVES else None
