# Copyright (C) 2014 Orange

# This software is distributed under the terms and conditions of the 'BSD
# 3-Clause' license which can be found in the 'LICENSE.txt' file in this package
# distribution or at 'http://opensource.org/licenses/BSD-3-Clause'.

#!/usr/bin/env python

"""Setup script for tinypyki."""

from distutils.core import setup

setup(name="tinypyki",
      description="A tiny openssl command line wrapper.",
      long_description="""Focus on your PKI and what you want of it, not
                          spending half an hour figuring out the basics
                          of openssl certificate generation.\n
                          \n""" + open("README.md", "r").read(),
      author="botview",
      author_email="b0tv13w@gmail.com",
      url="https://github.com/Orange-OpenSource",
      license="BSD 3-Clause",
      version="0.1",
      packages=["tinypyki",],
      py_modules=["tinypyki"],
      classifiers=["License :: OSI Approved :: BSD License",
                   "Natural Language :: English",
                   "Operating System :: POSIX :: Linux",
                   "Programming Language :: Python :: 3",
                   "Environment :: Console",
                   "Development Status :: 4 - Beta",
                   "Topic :: Security",
                   "Topic :: Internet",
                   "Topic :: Education :: Testing",
                   "Intended Audience :: End Users/Desktop",
                   "Intended Audience :: Education",
                   "Intended Audience :: Developers",
                   "Intended Audience :: Information Technology",
                   "Intended Audience :: System Administrators",
                   "Intended Audience :: Telecommunications Industry"]
      )
