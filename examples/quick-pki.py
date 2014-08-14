#!/usr/bin/env python

"""A fourth example to get started with tinypyki.

Create an LTE PKI and revoke a subtree.
"""

import os

import tinypyki as tiny

print("Create an lte-pki")
pki = tiny.PKI("lte-pki")

print("Create a root-ca node which issues two certificates, one for the core-ca, another for endoe-ca")
root_ca   =  tiny.Node(nid = "root-ca",  pathlen = 4,        sign_list = ["core-ca", "enode-ca"])

print("Create a core-ca and an enode-ca")
net_cas   = [tiny.Node(nid = "core-ca",  issuer = "root-ca", sign_list = ["mme", "msc", "sgsn", "hss"]), 
             tiny.Node(nid = "enode-ca", issuer = "root-ca", sign_list = ["alu-ca", "huawei-ca", "xp-ca"])]

print("Create nodes issued by core-ca")
core_usrs = [tiny.Node(nid = "mme",  ntype = "u", issuer = "core-ca"), 
             tiny.Node(nid = "msc",  ntype = "u", issuer = "core-ca"), 
             tiny.Node(nid = "sgsn", ntype = "u", issuer = "core-ca"), 
             tiny.Node(nid = "hss",  ntype = "u", issuer = "core-ca")]

print("Create eNodeB segmentation, one ca per constructor plus an experimental ca")
node_cas  = [tiny.Node(nid = "alu-ca",    issuer = "enode-ca", sign_list = ["alu-enb1", "alu-enb2", "alu-enb3"]), 
             tiny.Node(nid = "huawei-ca", issuer = "enode-ca", sign_list = ["huawei-enb1", "huawei-enb2", "huawei-enb3"]),
             tiny.Node(nid = "xp-ca",     issuer = "enode-ca", sign_list = ["xp-enb1", "xp-enb2"])]

print("Create eNodeB user certificates")
node_usrs = [tiny.Node(nid = "alu-enb1",    ntype = "u", issuer = "alu-ca",    key_len = 512), 
             tiny.Node(nid = "alu-enb2",    ntype = "u", issuer = "alu-ca",    key_len = 1024), 
             tiny.Node(nid = "alu-enb3",    ntype = "u", issuer = "alu-ca",    key_len = 2048), 
             tiny.Node(nid = "huawei-enb1", ntype = "u", issuer = "huawei-ca", key_len = 512), 
             tiny.Node(nid = "huawei-enb2", ntype = "u", issuer = "huawei-ca", key_len = 1024), 
             tiny.Node(nid = "huawei-enb3", ntype = "u", issuer = "huawei-ca", key_len = 2048), 
             tiny.Node(nid = "xp-enb1",     ntype = "u", issuer = "xp-ca",     key_len = 4096), 
             tiny.Node(nid = "xp-enb2",     ntype = "u", issuer = "xp-ca",     key_len = 8192)]

print("Insert root and all subsequent nodes to the pki")
tiny.do.insert(root_ca, pki)
for node in net_cas + core_usrs + node_cas + node_usrs:
    tiny.do.insert(node, pki)

print("Set node subjects accordingly")
for nid in pki.nodes:
    tiny.change.subj(pki.nodes[nid], cn=nid + ".operator.com")

print("Create everything, including p12 bundle")
tiny.do.everything(pki, pkcs12=True)

# Uncomment this if you wish to see the contents of all the files
# print("Showing the contents of all files")
# for node in pki.nodes.values():
#     tiny.show(node.key_path)
#     tiny.show(node.csr_path)
#     tiny.show(node.cert_path)
#     tiny.show(node.crl_path)

print("Observe xp-ca's issuer crl before revocation")
tiny.show(pki.nodes[pki.nodes["xp-ca"].issuer].crl_path)

print("Revoke xp-ca")
# Valid reasons: "unspecified", "keycompromise", "cacompromise", "affiliationchanged", "superseded", "cessationofoperation", "certificatehold", "removefromcrl"
tiny.do.revoke(pki.nodes["xp-ca"], reason="cessationofoperation")

print("Observe xp-ca's issuer crl after revocation")
tiny.show(pki.nodes[pki.nodes["xp-ca"].issuer].crl_path)

print("Observe pki changes")
tiny.show(pki)

# Uncomment this if you wish to delete the files
# print("Cleaning up the work direcotry")
# tiny.do.clean(pki)
