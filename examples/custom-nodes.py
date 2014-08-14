#!/usr/bin/env python

"""A second example to get started with tinypyki.

Toying with custom nodes and using helper functions.
"""

import os

import tinypyki as tiny

print("Creating a pki instance named \"custom-nodes\"")
pki = tiny.PKI("custom-nodes")

print("Printing the way a it looks")
tiny.show(pki)

print("Creating the pki environment on disk")
tiny.do.gen.env(pki)

print("Creating a node called \"fancy-server\" with an instantiation example")
ca_node = tiny.Node(nid         = "fancy-ca",      # node ID, default is a uuid4
                    ntype       = "ca",            # node type ("ca" for CAs or "u" for users), default "ca"
                    key_len     = 4096,            # key length, a power of two 2^n
                    subj        = "/C=EM/L=Mudlands/ST=Mudcity/O=Dilbert.Ltd/OU=R\\&D/emailAddress=pointy_haired_boss@dilbert.el/CN=dilbert.el/", # subject, default is a Dilbert reference
                    san         = "",              # subject alternative name (ip, dns, mail...)
                    life        = 42,              # certificate validity time
                    csr_digest  = "md5",           # csr digest algorithm ("md5" or "sha1"), default is "sha1"
                    cert_digest = "sha1",          # certificate digest algorithm ("md5" or "sha1"), default is "sha1"
                    crl_digest  = "md5",           # crl digest algorithm ("md5" or "sha1"), default is "sha1"
                    crl_life    = 21,              # crl validity time (minimum between certificate life and this value)  
                    pathlen     = 1,               # up to how many hierarchy levels underneath can be added
                    sign_list   = ["fancy-server"] # list of node IDs for which this node is the CA     
                   )

print("Creating a node default node and changing it with the helper functions")
user_node = tiny.Node()

print("Changing the node's unique id to \"fancy-user\"")
tiny.change.nid(user_node, "fancy-user")
print("Setting its type to \"u\" for user")
tiny.change.ntype(user_node, "u")
print("Specifying its issuer as \"fancy-ca\"")
tiny.change.issuer(user_node, "fancy-ca")
print("Setting its RSA key size to 4096")
tiny.change.keysize(user_node, 4096)
print("Setting its validity to 10 days")
tiny.change.life(user_node, 10)
print("Setting its subject, do note that you need to escape special characters as you would in bash")
tiny.change.subj(user_node, country="FR", state="Ile\ de\ France", city="Paris", organisation="Fashionable.Ltd", department="Marketing", email="regis@aol.fr", cn="xkcd.org")

print("Observe the \"fancy-ca\" node")
tiny.show(ca_node)
print("Observe the \"fancy-user\" node")
tiny.show(user_node)

print("Inserting both ndoes to the pki")
tiny.do.insert(ca_node, pki)
tiny.do.insert(user_node, pki)

# from this point on, you can access both nodes through pki.nodes["<nid>"]
# where <nid> is their respective node ids ("fancy-ca" and "fancy-user")

print("Observe changes to the pki")
tiny.show(pki)
print("Observe changes to the \"fancy-ca\" node")
tiny.show(ca_node)
print("Observe changes to the \"fancy-user\" node")
tiny.show(user_node)

print("Generate all key files")
tiny.do.keys(pki)

print("Generate all csrs")
tiny.do.csrs(pki)

print("Generate all certs")
tiny.do.certs(pki)

print("Generate CRLs for relevant nodes")
tiny.do.crls(pki)

print("Display contents of each respective file")
for nid in pki.nodes:
    tiny.show(pki.nodes[nid].key_path)
    tiny.show(pki.nodes[nid].csr_path)
    tiny.show(pki.nodes[nid].cert_path)
    tiny.show(pki.nodes[nid].crl_path)

print("Observe the changes to the pki")
tiny.show(pki)
