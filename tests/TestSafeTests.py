#!/usr/bin/env python
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
""" Test the pypwsafe API - Provides tests based on the different test safes. 

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
"""
import unittest
import os, os.path, sys
from tempfile import mkdtemp
from shutil import rmtree, copyfile
# Password to decrypt all test safes
STANDARD_TEST_SAFE_PASSWORD = 'bogus12345'

class TestSafeTestBase(unittest.TestCase):
    # Should be overridden with a test safe file name. The path should be relative to the test_safes directory.
    # All test safes must have the standard password (see above) 
    testSafe = None
    # Automatically open safes
    autoOpenSafe = True
    # How to open the safe
    autoOpenMode = "RO"
    
    def setUp(self):        
        assert self.testSafe
        
        self.safeLoc = os.path.join("../test_safes", self.testSafe)
        assert os.access(self.safeLoc, os.R_OK)
        
        # Make a temp dir and make a copy
        self.safeDir = mkdtemp(prefix = "safe_test_%s" % type(self).__name__)
        
        # COpy the safe
        self.ourTestSafe = os.path.join(
                                        self.safeDir,
                                        os.path.basename(self.testSafe),
                                        )
        copyfile(self.safeLoc, self.ourTestSafe)
        
        from pypwsafe import PWSafe3
        if self.autoOpenSafe:
            self.testSafeO = PWSafe3(
                                     filename = self.ourTestSafe,
                                     password = STANDARD_TEST_SAFE_PASSWORD,
                                     mode = self.autoOpenMode,
                                     )
        else:
            self.testSafeO = None
        
    def tearDown(self):
        try:
            rmtree(self.safeDir)
        except:
            pass
