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
''' Run unit tests
Created on Jan 19, 2013

@author: Paulson McIntyre (GpMidi) <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
'''
import unittest
import os, os.path, sys

import logging
logging.basicConfig(
                    level = logging.DEBUG,
                    filename = '/tmp/pypwsafe_unittests.log',
                    filemode = 'w',
                    )

from PWSv3Headers import *

if __name__ == '__main__':
    sys.path.append("../src")
    unittest.main()
