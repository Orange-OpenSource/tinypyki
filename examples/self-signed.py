#!/usr/bin/env python

"""A first example to get started with tinypyki.

Toying with self-signed certificates and manually creating everything.
"""

import os

import tinypyki as tiny

print("Creating a pki instance named \"self-signed\"")
pki = tiny.PKI("self-signed")

print("Printing the way a it looks")
tiny.show(pki)

print("Creating the pki environment on disk")
tiny.do.gen.env(pki)

print("Creating a node called \"server\" of type \"u\" for user")
node = tiny.Node(nid = "server", ntype = "u")

print("Printing the node as is, before it is inserted to the pki")
tiny.show(node)

print("Insert node to the pki")
tiny.do.insert(node, pki)

# From this point on, an alternative way to access node is by using pki.nodes["server"] 

print("Observe changes to the pki")
tiny.show(pki)
print("Observe changes to the node")
tiny.show(node)

print("Generate the key for the node")
tiny.do.gen.key(node)

print("Generate the csr for the node")
tiny.do.gen.csr(node)

print("Generate the cert for the node")
tiny.do.gen.cert(node)

print("Show the node's key")
tiny.show(node.key_path)
print("Show the node's csr")
tiny.show(node.csr_path)
print("Show the node's cert")
tiny.show(node.cert_path)

print("Observe the changes to the pki")
tiny.show(pki)
