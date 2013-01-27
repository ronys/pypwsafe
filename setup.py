#!/usr/bin/python
''' Install pypwsafe
Created on Jul 23, 2011

@author: paulson mcintyre <paul@gpmidi.net>
'''
from distutils.core import setup, Extension
import sys
VERSION = "0.3"

# Generate docs
import os
sys.path.append('src')
sys.path.append('tests')
sys.path.append('pwsafecli')

setup(name = "python-pypwsafe",
      version = VERSION,
      description = "Python interface to Password Safe v3 files",
      author = "Paulson McIntyre",
      author_email = "paul@gpmidi.net",
      license = "GPL",
      long_description = \
"""
A Python interface for reading and writing Password Safe v3 
files. Includes support for Password Safe versions V3.01 
through V3.29Y.   
""",
      url = 'https://github.com/ronys/pypwsafe',
      packages = [
                'pypwsafe',
                  ],
      package_dir = {
                   '':'src',
                     },
      scripts = [
                 "pwsafecli/pwsafecli.py",
                 "pwsafecli/psafedump",
                 ],
      data_files = [
				
				],
      )
