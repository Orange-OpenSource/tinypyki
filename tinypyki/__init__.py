# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

"""A tiny openssl command line wrapper."""

__version__ = """0.1 - alpha"""

"""Populate tinypyki namespace."""

import os
import sys

from .pki  import *
from .show import show
from .     import do, change
