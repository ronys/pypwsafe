#!/usr/bin/python
''' Install pypwsafe
Created on Jul 23, 2011

@author: paulson mcintyre <paul@gpmidi.net>
'''
from distutils.core import setup, Extension
import sys
VERSION = "0.1"

# Generate docs
import os
sys.path.append('src')

setup(name = "python-pypwsafe",
      version = VERSION,
      description = "Python interface to Password Safe files",
      author = "Paulson McIntyre",
      author_email = "paul@gpmidi.net",
      license = "GPL",
      long_description = \
"""
Python interface to Password Safe files. 
""",
      url = 'https://github.com/ronys/pypwsafe',
      packages = [
                'pypwsafe',
                  ],
      package_dir = {
                   '':'src',
                     },
      scripts = [
                 "psafedump",
                 ],
      )
