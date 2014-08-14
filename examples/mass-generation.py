#!/usr/bin/env python

"""A third example to get started with tinypyki.

Toying with mass certificate generation.
"""

import os

import tinypyki as tiny

print("Creating a pki instance named \"mass-pki\"")
pki = tiny.PKI("mass-pki")

print("Create the \"root-ca\"")
root_ca =  tiny.Node(nid = "root-ca",  pathlen = 1, san="email=dev.null@hexample.com")

print("Create 10 sub nodes")
targets = [tiny.Node(nid = "target-{0}".format(i), issuer = "root-ca", ntype="u", san="ip=192.168.0.{0}, dns=hexample.com".format((175+i)%256)) for i in range(10)]

print("Insert the root-ca then all nodes in the pki")
tiny.do.insert(root_ca, pki)
for node in targets:
    tiny.change.subj(node, cn=node.nid + "-dummy-hexample")
    tiny.do.insert(node, pki)

print("Create everything, including p12 bundles")
tiny.do.everything(pki, pkcs12 = True)

print("Observe the pki changes")
tiny.show(pki)

# Uncomment this if you wish to see the contents of all the files
# print("Showing the contents of all files")
# for node in pki.nodes.values():
#     tiny.show(node.key_path)
#     tiny.show(node.csr_path)
#     tiny.show(node.cert_path)
#     tiny.show(node.crl_path)

print("Revoking every other certificate")
for node in pki.nodes.values():
    if node.nid.startswith("target"):
        if not int(node.nid.split("-")[-1])%2:
            # Valid reasons: "unspecified", "keycompromise", "cacompromise", "affiliationchanged", "superseded", "cessationofoperation", "certificatehold", "removefromcrl"
            tiny.do.revoke(node, reason="keycompromise")

print("Observe the crl changes of the root-ca")
tiny.show(pki.nodes["root-ca"].crl_path)

print("Create the verification environment")
tiny.do.verifyenv(pki, create=True)

print("Verify every file related to root-ca")
tiny.do.verify(pki.nodes["root-ca"])
# You can verify specific elements, by specifying "key", "csr", "cert", "crl" or "pkcs12"
# tiny.do.verify(pki.nodes["root-ca"], "key")
# You can verify the whole pki as follows
# tiny.do.verify_all(pki)

print("Destroy the verification environment")
tiny.do.verifyenv(pki, create=False)

# Uncomment this if you wish to delete the files
# print("Cleaning up the work direcotry")
# tiny.do.clean(pki)
