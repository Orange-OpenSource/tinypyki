1. Requirements:
================

- You need a sufficiently up to date version of openssl that supports the command line arguments embedded in tinypyki
- For ECC, make sure you compiled openssl with ECC support (disabled by default due to patent issues, USE=-bindist on gentoo)

2. Installation:
================
Create bundle:      $ python setup.py sdist --formats=gztar,bztar
Install tinypyki:   $ sudo python setup.py install --record files.txt
Uninstall tinypyki: $ cat files.txt | xargs rm -rf

3. Getting started:
===================

Look at the examples.
python -i your_script.py, help() and dir() are your friends.

4. Remarks:
===========

If you are proficient with openssl, feel free to improve on this to suit your needs.
This is not meant to be a secure use example, most passphrases are disabled or removed for automation.

Special thanks to cmaxis for all the PKI-related advice and alpha-testing.
