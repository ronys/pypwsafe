#!/usr/bin/python
#===============================================================================
# This file is part of PyPWSafe.
#
#    PyPWSafe is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    PyPWSafe is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with PyPWSafe.  If not, see http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
#===============================================================================
''' Install pypwsafe
Created on Jul 23, 2011

@author: paulson mcintyre <paul@gpmidi.net>
'''
from setuptools import setup
import sys
VERSION = "0.3"

# Generate docs
import os
sys.path.append('src')
sys.path.append('tests')
sys.path.append('pwsafecli')

setup(
      name = "python-pypwsafe",
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
      data_files = [],
      classifiers = [
          "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Development Status :: 4 - Beta",
          "Operating System :: MacOS",
          "Operating System :: POSIX",
          "Intended Audience :: System Administrators",
          "Intended Audience :: Developers",
          "Topic :: Security :: Cryptography",
          "Topic :: Utilities",
          "Topic :: System :: Systems Administration",
      ],
      keywords = 'password login authentication passwordsafe security psafe3',
      install_requires = [
        'distribute',
        'python2-mcrypt',
        'hashlib',
        'pycrypto',
      ],
      )
