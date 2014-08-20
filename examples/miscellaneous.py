#!/usr/bin/env python

"""A fifth example to get started with tinypyki.

Miscellaneous tips and tricks.
"""

import os

import tinypyki as tiny

print("Create a pki toy chain, with some nodes sporting ECC keys")
pki = tiny.PKI("misc-examples")

root_ca   = tiny.Node(nid = "root-ca",                             pathlen = 3,                      life = 100, 
                      san = "email=cartman@southpark.tv",          crl_dps ="mom.net",               key_len=2048*2)
sub_ca    = tiny.Node(nid = "sub-ca",                              issuer  = "root-ca",              life = 99,  
                      san = "dns=kyle.southpark.tv",               crl_dps ="canada.net",            curve_name="secp384r1")
under_ca  = tiny.Node(nid = "under-ca",                            issuer  = "sub-ca",               life = 98,  
                      san = "ip=1.0.1.0",                          crl_dps ="wendy.net",             curve_name="c2pnb163v3")
user      = tiny.Node(nid = "user",                                issuer  = "under-ca",             life = 12,  
                      san = "uri=https://omg.you.killed.kenny.tv", crl_dps ="omg.net, bastards.net", curve_name="sect409k1")

tiny.change.subj(root_ca,  cn = "cartman", city = "southpark")
tiny.change.subj(sub_ca,   cn = "kyle",    city = "southpark")
tiny.change.subj(under_ca, cn = "stan",    city = "southpark")
tiny.change.subj(user,     cn = "kenny",   city = "southpark")

tiny.do.insert(root_ca, pki)
tiny.do.insert(sub_ca, pki)
tiny.do.insert(under_ca, pki)
tiny.do.insert(user, pki)

print("Create and verify everything")
tiny.do.everything(pki, pkcs12=True)

print("Observe the pki and check that everything fits nicely")
tiny.show(pki)

# Uncomment this if you wish to see the contents of all the files
# print("Showing the contents of all files")
# for node in pki.nodes.values():
#     tiny.show(node.key_path)
#     tiny.show(node.csr_path)
#     tiny.show(node.cert_path)
#     tiny.show(node.crl_path)

tiny.do.verifyenv(pki,) # default is create=True anyway
tiny.do.verify_all(pki)
tiny.do.verifyenv(pki, create=False)

######################################
# Various ways to iterate over nodes #
######################################

print("Various ways to iterate over nodes")
print([nid for nid in pki.nodes])
print([node.nid for node in pki.nodes.values()])
print(pki.ordered())

# Through pki.nodes
# for nid in pki.nodes:
#   tiny.show(pki.nodes[nid])

# for node in pki.nodes.values():
#   tiny.show(node)

# This ensures you are iterating from top to bottom (dependency wise)
# for nid in pki.ordered()
#   tiny.show(node)

#########################################
# Various ways to iterate over subtrees #
#########################################

print("Various ways to iterate over a subtree")
print([nid for nid in pki.nodes["sub-ca"].subtree()])
print([nid for nid in pki.nodes["sub-ca"].subtree(including=True)])

# Iterate over subtree of node (including itself)
for nid in pki.nodes["root-ca"]:
    print(nid)

# Access a specific node from a node's subtree
# IndexError is raised if nid not in subtree (including self)
print(pki.nodes["root-ca"]["sub-ca"])

# Check if an index is in a node's subtree
print("sub-ca" in pki.nodes["root-ca"])
print("root-ca" in pki.nodes["sub-ca"])

# Keep in mind that each node has a reference to the pki it belongs to once it has been inserted

#############################
# Relative dependency order #
#############################

print("Relative dependency order")
# All nodes in relative dependency order (top to bottom)
print(pki.ordered())
# All nodes in relative dependency oder (bottom to top)
print(pki.ordered()[::-1])
# Alternative
# t = pki.ordered()
# t.reverse() 
# print(t)

# All subtree nodes in relative dependency order (top to bottom)
print(pki.nodes["sub-ca"].subtree(including=True))
# All subtree nodes in relative dependency order (bottom to top)
print(pki.nodes["sub-ca"].subtree(including=True)[::-1])
# Alternative
# t = pki.nodes["sub-ca"].subtree(including=True)
# t.reverse() 
# print(t)

# Show a node's trust chain (bottom to top)
print(pki.trust_chain("user"))
# Show a node's trust chain (top to bottom)
print(pki.trust_chain("user")[::-1])
# Alternative
# t = pki.trust_chain("user")
# t.reverse()
# print(t)

#########################
# Comparison operations #
#########################

print("Comparison operations between nodes")
# Check if two nodes are equal
print(pki.nodes["root-ca"] == pki.nodes["root-ca"])
print(pki.nodes["root-ca"] == pki.nodes["sub-ca"])

# Check if two nodes are different
print(pki.nodes["root-ca"] != pki.nodes["sub-ca"])
print(pki.nodes["root-ca"] != pki.nodes["root-ca"])

# Node along a trust chain
print(pki.nodes["root-ca"] <  pki.nodes["root-ca"])
print(pki.nodes["root-ca"] <  pki.nodes["sub-ca"])
print(pki.nodes["sub-ca"]  <  pki.nodes["root-ca"])

# Node along a trust chain
print(pki.nodes["root-ca"] >  pki.nodes["root-ca"])
print(pki.nodes["root-ca"] >  pki.nodes["sub-ca"])
print(pki.nodes["sub-ca"]  >  pki.nodes["root-ca"])

# Node along a trust chain
print(pki.nodes["root-ca"] <= pki.nodes["root-ca"])
print(pki.nodes["root-ca"] <= pki.nodes["sub-ca"])
print(pki.nodes["sub-ca"]  <= pki.nodes["root-ca"])

# Node along a trust chain
print(pki.nodes["root-ca"] >= pki.nodes["root-ca"])
print(pki.nodes["root-ca"] >= pki.nodes["sub-ca"])
print(pki.nodes["sub-ca"]  >= pki.nodes["root-ca"])

##################################
# A few draft management methods #
##################################

print("A few draft management methods")
# Renew a CRL (note, check for life prior)
# note, life is min(life specified & issuer cert life)
tiny.do.renew_crl(pki.nodes["root-ca"], life=10)
# old file is saved as .old, otherwise specify state=False

# Renew branch
tiny.do.renew_branch(pki.nodes["under-ca"], including=True)

# Resume management after initial creation
save_path = pki.path["state"]
loaded_pki = tiny.do.load(save_path)
tiny.show(loaded_pki)

# Create a keystore
# Valid formats: cert, cer, crt or pem for certificates only, p12 or pkcs12 for bundles
tiny.do.keystore(pki.nodes["user"], format="cert")
# Keystores are in the cert directory with a filename nid.keystore.cert.pem extension
tiny.do.keystore(pki.nodes["user"], format="p12")
# Keystores are in the cert directory with a filename nid.keystore.p12 extension

# Show an ecc domain key
tiny.show(pki.nodes["user"].key_path)

# When done, clean working directory
# tiny.do.clean(pki)
