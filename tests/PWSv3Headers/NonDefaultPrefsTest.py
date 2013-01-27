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
''' Test non-default preferences for the DB
Created on Jan 19, 2013

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
'''
import unittest
import os, os.path, sys

from TestSafeTests import TestSafeTestBase, STANDARD_TEST_SAFE_PASSWORD


class NonDefaultPrefsTest_DBLevel(TestSafeTestBase):
    # Should be overridden with a test safe file name. The path should be relative to the test_safes directory.
    # All test safes must have the standard password (see above) 
    testSafe = 'NonDefaultPrefsTest.psafe3'
    # Automatically open safes
    autoOpenSafe = False
    # How to open the safe
    autoOpenMode = "RO"

    def _openSafe(self):
        from pypwsafe import PWSafe3
        self.testSafeO = PWSafe3(
                                 filename = self.ourTestSafe,
                                 password = STANDARD_TEST_SAFE_PASSWORD,
                                 mode = self.autoOpenMode,
                                 )

    def test_open(self):
        self.testSafeO = None
        self._openSafe()
        self.assertTrue(self.testSafeO, "Failed to open the test safe")


class NonDefaultPrefsTest_RecordLevel(TestSafeTestBase):
    # Should be overridden with a test safe file name. The path should be relative to the test_safes directory.
    # All test safes must have the standard password (see above) 
    testSafe = 'NonDefaultPrefsTest.psafe3'
    # Automatically open safes
    autoOpenSafe = True
    # How to open the safe
    autoOpenMode = "RO"
    
    def test_defaults(self):
        from pypwsafe.consts import conf_bools, conf_ints, conf_strs, ptDatabase
        prefs = self.testSafeO.getDbPrefs()
        self.assertTrue(len(prefs) > 0, "Expected some prefs to be set")
        
        # print repr(prefs)
    
        for typeS in [conf_bools, conf_ints, conf_strs]:
            for name, info in typeS.items():
                if info['type'] == ptDatabase:
                    self.assertTrue(name in prefs, "Didn't find %r in %r" % (name, prefs))
                else:
                    self.assertFalse(name in prefs, "Found %r of type %r in %r when it's not a DB level setting" % (name, info['type'], prefs))

# FIXME: Add a check to make sure default values aren't being saved
# FIXME: Add save test

