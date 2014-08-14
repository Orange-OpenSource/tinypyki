# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

"""Definition of tinypyki classes PKI() and Node()."""

import os
import uuid

from .macros import *

class PKI():
    """A PKI tree structure abstraction and related methods."""

    def __init__(self, pki_id=None):
        """Attributes:

        .pki_id -- a unique PKI instance identifier (default uuid4)
        .serial -- internal tracking serial number for certificates
        .path   -- a dictionary holding references to various paths, valid indexes:
                   * path["conf"]       -- reserved for future use.
                   * path["wdir"]       -- work directory, where all instance data is stored on disk
                   * path["openssl"]    -- path to openssl binary (default /usr/bin/openssl)
                   * path[".keys"]      -- directory holding all the generated key files
                   * path["csrs"]       -- directory holding all the generated csr files
                   * path["crls"]       -- directory holding all the generated crl files
                   * path["sans"]       -- directory holding all the subject alternative name files
                   * path["index"]      -- openssl required index file
                   * path["config.cnf"] -- openssl required configuration file
                   * path["state"]      -- path to the saved instance state (picked file)
        .nodes  -- a dictionary of all the nodes in the pki { "unique_node_id": Node_Object_Reference }
        """

        self.id     = pki_id if pki_id else str(uuid.uuid4())
        self.serial = "{0:02x}".format(1)
        self.path   = {"wdir"       : os.getcwd() + "/instances/{0}".format(pki_id),
                       "openssl"    : "/usr/bin/openssl",
                       ".keys"      : None,
                       "csrs"       : None,
                       "certs"      : None,
                       "crls"       : None,
                       "sans"       : None,
                       "index"      : None,
                       "config.cnf" : None,
                       "state"      : None
                       }
        self.nodes  = {}
        for k in self.path.keys():
            self.path[k] = os.path.join(self.path["wdir"], k) if not self.path[k] else self.path[k]

    def __repr__(self):
        """Formal PKI representation."""
        return "PKI(\"{0}\")".format(self.id)

    def __str__(self):
        """String representation (print)"""
        pretty_print = "PKI instance:\n"
        for attr in sorted(self.__dict__):
            if isinstance(self.__dict__[attr], dict):
                pretty_print += "\t`-> {0:<10}:\n".format(attr)
                for idex in self.__dict__[attr]:
                    pretty_print += "\t\t`-> {0:<10} = {1}\n".format(idex, self.__dict__[attr][idex])
            else:
                pretty_print += "\t`-> {0:<10} = {1}\n".format(attr, self.__dict__[attr])
        return pretty_print

    def increment(self):
        """Internal use for incrementing the serial."""
        self.serial = "{0:02x}".format(int(self.serial, 16) + 1)

    def ordered(self):
        """Return a list of node ids in a relative order.

        Leftmost node ids are to be created before the rightmost nodes are,
        to solve the issuer hierarchy problem.
        """
        ordered_list = []
        while len(ordered_list) != len(self.nodes):
            for node in self.nodes.values():
                if not node.nid in ordered_list:
                    if node.issuer == node.nid or node.issuer in ordered_list:
                        ordered_list.append(node.nid)
        return ordered_list

    def trust_chain(self, nid):
        """Return the trust chain, from this node to the root node.

        The trust chain is the list of node ids from nid itself, its issuer, all
        the way to the root.

        To get the reverse trust chain, the chain of issuers, from root to this 
        nid, use return value with [::-1].
        """
        chain, ca_id = [], nid
        if not nid in self.nodes:
            return chain
        else:
            chain.append(ca_id)
            while ca_id != self.nodes[ca_id].issuer:
                ca_id = self.nodes[ca_id].issuer
                chain.append(ca_id)
            return chain

class Node():
    """A PKI tree Node abstraction and related methods."""
    def __init__(self,
                 pki         = None,
                 nid         = None, 
                 ntype       = None,
                 issuer      = None,
                 key_len     = None, 
                 subj        = None, 
                 san         = None,
                 san_id      = None,  
                 life        = None, 
                 csr_digest  = None, 
                 cert_digest = None,
                 crl_digest  = None,
                 crl_life    = None,
                 crl_dps     = None, 
                 pathlen     = None,
                 sign_list   = None,
                 key_path    = None, 
                 csr_path    = None, 
                 cert_path   = None,
                 crl_path    = None,
                 p12_path    = None,
                 curve_name  = None):
        """Attributes:

        .pki         -- reference to the PKI instance it belongs to (None if not inserted)
        .nid         -- a unique node id string (default uuid4)
        .ntype       -- node type, either "ca" for Certificate Authority or "u" for end User
        .issuer      -- node id of the issuing node (nid == issuer translates to self-signed)  else .nid
        .key_len     -- RSA key length (default 2048), must be in SIZES
        .subj        -- node's subject (see tinypyki.change)
        .san         -- node's subject alternative name (see tinypyki.change)
        .san_id      -- internal value, subject alternative name's unique id used as PKI.path["sans"] index
        .life        -- certificate validity in days (default 1), must be >= 1
        .csr_digest  -- digest algorithm used for signing this node's CSR (default "sha1"),
                        must be a value defined in DIGESTS
        .cert_digest -- digest algorithm used for signing this node's CERT (default "sha1"),
                        must be a value defined in DIGESTS
        .crl_digest  -- digest algorithm used for signing this node's CSR (default "sha1"),
                        must be a value defined in DIGESTS
        .crl_life    -- crl validity in days (default 1), 
                        must be 1 <= crl_life <= crl_life
        .crl_dps     -- crl distribution point(s), a string of comma separated URIs (default None)
        .pathlen     -- path length, the maximum number of hierarchy levels between this node and a leaf,
                        this value is handled automatically and only roots (self-signed) nodes should have it set, 
                        user nodes default to 0
        .sign_list   -- a list of node ids for which this node is the issuer
        .key_path    -- filepath to the generated key file for this node
        .csr_path    -- filepath to the generated csr file for this node
        .cert_path   -- filepath to the generated cert file for this node
        .crl_path    -- filepath to the generated crl file for this node
        .p12_path    -- filepath to the generated p12 file for this node
        ._status     -- an internal status indicator for this node helping to identify what next needs to be generated
        ._itergen    -- an internal attribute used for iterations
        .curve_name  -- the curve name to be used if ECC is desired, 
                        must be defined in ECC_CURVES (default None), 
                        see tinypyki.gen.ecc_key
        """
    
        self.pki         = pki
        self.nid         = str(nid)            if nid         else str(uuid.uuid4())
        self.ntype       = ntype.lower()       if ntype       and ntype.lower()       in NTYPES     else "ca"
        self.issuer      = issuer              if issuer      else self.nid
        self.key_len     = int(key_len)        if key_len     else 2048
        self.subj        = subj                if subj        else "/C=EL/ST=Mudlands/L=Mudcity/O=Dilbert.Ltd/OU=R\\&D/emailAddress=pointy_haired_boss@dilbert.el/CN=dilbert.el"
        self.san         = san                 if san         else None
        self.san_id      = san_id              if san_id      else None
        self.life        = int(life)           if life        else 1
        self.csr_digest  = csr_digest.lower()  if csr_digest  and csr_digest.lower()  in DIGESTS    else "sha1"
        self.cert_digest = cert_digest.lower() if cert_digest and cert_digest.lower() in DIGESTS    else "sha1"
        self.crl_digest  = crl_digest.lower()  if crl_digest  and crl_digest.lower()  in DIGESTS    else "sha1"
        self.crl_life    = int(crl_life)       if crl_life    else 1
        self.crl_dps     = crl_dps             if crl_dps     else None
        self.pathlen     = pathlen             if pathlen     else 0
        self.sign_list   = sign_list           if isinstance(sign_list, list) else [self.nid] if self.nid == self.issuer else []
        self.key_path    = key_path            if key_path    else None
        self.csr_path    = csr_path            if csr_path    else None
        self.cert_path   = cert_path           if cert_path   else None
        self.crl_path    = crl_path            if crl_path    else None
        self.p12_path    = p12_path            if p12_path    else None
        self._status     = "key"
        self._itergen    = None
        self.curve_name  = curve_name          if curve_name  and curve_name          in ECC_CURVES else None

    def __repr__(self):
        """Formal Node representation."""
        return "Node({0})".format(", ".join(("{0}={1}".format(attr, self.__dict__[attr]) for attr in self.__dict__)))

    def __str__(self):
        """String Node representation (print)"""
        pretty_print = "Node {0}:\n".format(self.nid)
        for attr in sorted(self.__dict__):
            pretty_print += "\t\t\t`-> {0:<11} = {1}\n".format(attr, self.__dict__[attr] if attr != "pki" else self.__dict__[attr].id if self.__dict__[attr] else None)
        return pretty_print

    def __eq__(self, other):
        """Equal nodes.

        Two nodes are equal if they are Nodes and all their members are equal.
        """
        return isinstance(other, Node) and all((self.__dict__[s] == other.__dict__[o] for s,o in zip(self.__dict__.keys(), other.__dict__.keys())))

    def __ne__(self, other):
        """Not equal."""
        return not self.__eq__(other)
    
    def __lt__(self, other):
        """Lower than.

        A node is said to be lower than another if it belongs to that other
        node's subtree.
        """
        return self.__ne__(other) and self.pki.id == other.pki.id and self.nid in other.subtree() 

    def __gt__(self, other):
        """Greater than.

        A node is said to be greater than another if that other node belongs to
        this node's subtree.
        """
        return isinstance(other, Node) and other.__lt__(self)

    def __le__(self, other):
        """Lower or equal."""
        return self.__eq__(other) or self.__lt__(other)

    def __ge__(self, other):
        """Greater or equal."""
        return self.__eq__(other) or self.__gt__(other)

    def __gen__(self):
        """Turn this node's subtree into a generator."""
        for nid in self.subtree(including=True):
            yield nid

    def __iter__(self):
        """Solves backward compatibility between python2 and python3."""
        self._itergen = self.__gen__()
        return self

    def __getitem__(self, nid):
        """Enables index access to a node within this node's subtree."""
        if nid in self.subtree(including=True):
            return self.pki.nodes[nid]
        else:
            raise IndexError

    def next(self):
        """Solves backward compatibility between python2 and python3."""
        return self.__next__()

    def __next__(self):
        """Enables ietation over a node's subtree."""
        try:
            return next(self._itergen)
        except StopIteration:
            self._itergen = None
            raise StopIteration

    def subtree(self, including=False):
        """Returns a list of node ids which have this node in their trust chain.

        including -- if True, includes this node's node id in the subtree (default False)
        """
        sub_list = [] if not including else [self.nid]
        for nid in self.sign_list:
            if not self.pki.nodes[nid].sign_list:
                sub_list.append(nid)
            else:
                if nid == self.nid:
                    continue
                sub_list += self.pki.nodes[nid].subtree(including=True)
        return sub_list

    def __contains__(self, nid):
        """Enables for quick checks if a node's node id is in this node's subtree (including itself)"""
        return isinstance(nid, str) and nid in self.subtree(including=True)
