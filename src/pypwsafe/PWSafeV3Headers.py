#!/usr/bin/env python
#===============================================================================
# SYMANTEC:     Copyright (C) 2009-2011 Symantec Corporation. All rights reserved.
#
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
""" Header objects for psafe v3
 
@author: Paulson McIntyre <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
"""
# Note: Use "=" in all packs to account for 64bit systems

from struct import unpack, pack
from errors import *
from consts import *
import os
import logging, logging.config
from uuid import UUID, uuid4
from pprint import pformat
from binascii import unhexlify

#logging.config.fileConfig('/etc/mss/psafe_log.conf')
log = logging.getLogger("psafe.lib.header")
log.debug('initing')

headers = { }

class _HeaderType(type):
    def __init__(cls, name, bases, dct):
        super(_HeaderType, cls).__init__(name, bases, dct)
        # Skip any where TYPE is none, such as the base class
        if cls.TYPE:
            headers[cls.TYPE] = cls

class Header(object):
    """A psafe3 header object. Should be extended. This also servers as a "unknown" header type.
    raw_data    string        Real data that was passed
    data        string        Raw data minus padding and headers
    len        long        Number of bytes of data. May not be present until data has been parsed
    readblock_f    function    Read in another block of data
    TYPE        int        Header type that IDs it in psafe3

    """
    # Auto-register new classes
    __metaclass__ = _HeaderType
    
    TYPE = None
    
    def __init__(self, htype, hlen, raw_data):
        self.data = raw_data[5:(hlen + 5)]
        self.raw_data = raw_data
        self.len = int(hlen)
        if type(self) != Header:
            assert self.TYPE == htype
        else:
            self.TYPE = htype
        self.parse()

    def parse(self):
        """Parse the header. Should be overridden. """
        pass

    def gen_blocks(self):
        """Returns the raw data that should be stuck in a psafe file"""
        return self.raw_data

    def __repr__(self):
        # Can no longer depend on raw_data existing
        #return "Header(%s,%d,%s)"%(repr(self.TYPE),self.len,repr(self.raw_data))
        s = self.serial()
        return "Header(%s,%d,%s)" % (repr(self.TYPE), len(s), repr(s))

    def __str__(self):
        return self.__repr__()

    def hmac_data(self):
        """Returns the data segments that should be used for the HMAC. See bug 1812081. """
        return self.serial()

    def serial(self):
        return self.data

    def serialiaze(self):
        serial = self.serial()
        log.debug("len: %s type: %s final: %s" % (len(serial), repr(chr(self.TYPE)), repr(pack('=lc', len(serial), chr(self.TYPE)))))
        padded = self._pad(pack('=lc', len(serial), chr(self.TYPE)) + serial)
        log.debug("Padded data %s" % repr(padded))
        return padded

    def _pad(self, data):
        """ Pad out data to 16 bytes """
        add_data = 16 - len(data) % 16
        if add_data == 16:
            add_data = 0
        padding = ''
        for i in xrange(0, add_data):
            padding += os.urandom(1)
        assert len(padding) == add_data
        assert len(data + padding) % 16 == 0
        return data + padding


class VersionHeader(Header):
    """Version header object
    version        int        Psafe version

>>> x=VersionHeader(0,2,'\x02\x00\x00\x00\x00\x02\x03\xb45C\x1d\xea\x08\x155\x02')
>>> str(x)
'Version=0x302'
>>> repr(x)
"VersionHeader(0,2,'\\x02\\x00\\x00\\x00\\x00\\x02\\x03\\xb45C\\x1d\\xea\\x08\\x155\\x02')"
>>> x.serial()
'\x02\x03'  
>>> x=VersionHeader(version=0x304)
>>> str(x)
'Version=0x304'
>>> x.serial()
'\x04\x03'  
    """
    TYPE = 0x00

    def __init__(self, htype = None, hlen = 2, raw_data = None, version = 0x305):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.version = version

    def parse(self):
        """Parse data"""
        self.version = unpack('=H', self.data)[0]

    def __repr__(self):
        return "Version" + Header.__repr__(self)

    def __str__(self):
        return "Version=%s" % hex(self.version)

    def serial(self):
        return pack('=H', self.version)

from uuid import UUID
class UUIDHeader(Header):
    """DB UUID
    uuid        uuid.UUID        Database uuid object
    
DHeader(1,16,'\x10\x00\x00\x00\x01\xbdV\x92{H\xdbL\xec\xbb+\xe90w5\x17\xa2P6b\xe8\x87\x0c\x83\n\xd8\x11\xd7')
>>> x.serial()
'\xbdV\x92{H\xdbL\xec\xbb+\xe90w5\x17\xa2'
>>> str(x)
"UUID=UUID('bd56927b-48db-4cec-bb2b-e930773517a2')"
>>> repr(x)
"UUIDHeader(1,16,'\\x10\\x00\\x00\\x00\\x01\\xbdV\\x92{H\\xdbL\\xec\\xbb+\\xe90w5\\x17\\xa2P6b\\xe8\\x87\\x0c\\x83\\n\\xd8\\x11\\xd7')"
    """
    TYPE = 0x01

    def __init__(self, htype = None, hlen = 16, raw_data = None, uuid = None):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            if uuid:
                self.uuid = uuid
            else:
                self.uuid = uuid4()

    def parse(self):
        """Parse data"""
        self.uuid = UUID(bytes = unpack('=16s', self.data)[0])

    def __repr__(self):
        return "UUID" + Header.__repr__(self)

    def __str__(self):
        return "UUID=%s" % repr(self.uuid)

    def serial(self):
        return pack('=16s', str(self.uuid.bytes))

class NonDefaultPrefsHeader(Header):
    """Version header object
    version         int         Psafe version
    opts            dict        All config options

K:V for opts: 
    

>>> x=NonDefaultPrefsHeader(2,70,'B 1 1 B 2 1 B 28 1 B 29 1 B 31 1 B 50 0 I 12 255 I 17 1 I 18 1 I 20 1 ')
>>> x=NonDefaultPrefsHeader(2,86,'B 1 1 B 2 1 B 28 1 B 29 1 B 31 1 B 50 0 I 12 255 I 17 1 I 18 1 I 20 1 S 3 \'adfasdfs"\' ')
# FIXME: Fill in tests
    """
    TYPE = 0x02

    def __init__(self, htype = None, hlen = 2, raw_data = None, **kw):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.opts = kw

    def parse(self):
        """Parse data"""
        self.opts = {}
        remander = self.data.split(' ')
        while len(remander) > 2:
            # Pull out the data
            rtype = str(remander[0])
            key = int(remander[1])
            value = str(remander[2])
            del remander[0:3]
            if rtype == "B":
                found = False
                for name, info in conf_bools.items():
                    if info['index'] == key:
                        found = True
                        break
                if not found:
                    raise ConfigItemNotFoundError, "%d is not a valid configuration item" % key
                if value == "0":
                    self.opts[name] = False
                elif value == "1":
                    self.opts[name] = True
                else:
                    raise PrefsValueError, "Expected either 0 or 1 for bool type, got %r" % value
            elif rtype == "I":
                found = False
                for name, info in conf_ints.items():
                    if info['index'] == key:
                        found = True
                        break
                if not found:
                    raise ConfigItemNotFoundError, "%d is not a valid configuration item" % key
                try:
                    value = int(value)
                except ValueError:
                    raise  PrefsDataTypeError, "%r is not a valid int" % value
                if info['min'] != -1 and info['min'] > value:
                    raise  PrefsDataTypeError, "%r is too small" % value
                if info['max'] != -1 and info['max'] < value:
                    raise  PrefsDataTypeError, "%r is too big" % value
                self.opts[name] = value
            elif rtype == "S":
                found = False
                for name, info in conf_strs.items():
                    if info['index'] == key:
                        found = True
                        break
                if not found:
                    raise ConfigItemNotFoundError, "%d is not a valid configuration item" % key
                # Remove "" or whatever the delimiter is 
                delm = value[0]
                if value[-1] == delm:
                    value = value[1:-1]
                else:
                    while not delm in remander[0] and len(remander) > 0:
                        value += remander[0]
                        del remander[0]
                    value = value[1:-1]
                # Save the pref
                self.opts[name] = value
            else:
                raise PrefsDataTypeError, "Unexpected record type for preferences %r" % rtype

    def __repr__(self):
        return "NonDefaultPrefs" + Header.__repr__(self)

    def __str__(self):
        return "NonDefaultPrefs=%s" % pformat(self.opts)

    def serial(self):
        ret = ''
        for name, value in self.opts.items():
            if not conf_types.has_key(name):
                raise PrefsValueError, "%r is not a valid configuration option" % name
            typ = conf_types[name]
            if type(value) != typ:
                raise PrefsDataTypeError, "%r is not a valid type for the key %r" % (type(value), name)
            if typ == bool:
                if value is True:
                    value = 1
                elif value is False:
                    value = 0
                else:
                    raise PrefsDataTypeError, "%r is not a valid value for the key %r" % (value, name)
                ret += "B %d %d " % (conf_bools[name]['index'], value)
            elif typ == int:
                value = int(value)
                ret += "I %d %d " % (conf_ints[name]['index'], value)
            elif typ == str:
                value = str(value)
                delms = list("\"'#?!%&*+=:;@~<>?,.{}[]()\xbb")
                delm = None
                while delm is None and len(delms) > 0:
                    if not delms[0] in value:
                        delm = delms[0]
                    else:
                        del delms[0]
                if not delm:
                    raise UnableToFindADelimitersError, "Couldn't find a delminator for %r" % value
                ret += "S %d %s%s%s " % (conf_strs[name]['index'], delm, value, delm)
            else:
                raise PrefsDataTypeError, "Unexpected record type for preferences %r" % typ
        return ret

# Header(3,14,'00000000000000'),
class TreeDisplayStatusHeader(Header):
    """ Tree display status (what folders are expanded/collapsed
  
    """
    TYPE = 0x03

    def __init__(self, htype = None, hlen = 1, raw_data = None, status = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.status = status

    def parse(self):
        """Parse data"""
        self.status = self.data

    def __repr__(self):
        return "Status" + Header.__repr__(self)

    def __str__(self):
        return "Status=%r" % self.status

    def serial(self):
        return self.status

# Header(4,4,'Ao\xc8L'),
from pypwsafe.PWSafeV3Records import parsedatetime, makedatetime
import time
class TimeStampOfLastSaveHeader(Header):
    """ Timestamp of last save. 
lastsave    time struct        Last save time of DB
    """
    TYPE = 0x04

    def __init__(self, htype = None, hlen = 1, raw_data = None, lastsave = time.gmtime()):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.lastsave = lastsave

    def parse(self):
        """Parse data"""
        time_data = self.data
        if len(time_data) == 8:
            time_data = unhexlify(time_data)
        self.lastsave = time.gmtime(unpack('=i', time_data)[0])

    def __repr__(self):
        return "LastSave" + Header.__repr__(self)

    def __str__(self):
        return "LastSave(%r)" % time.strftime("%a, %d %b %Y %H:%M:%S +0000", self.lastsave)

    def serial(self):
        return makedatetime(self.lastsave)

#TODO: Add support for this header type
#class WhoLastSavedHeader(Header):
#    """ User who last saved the DB.     DEPRECATED
#    """
#    TYPE = 0x05
#
#    def __init__(self, htype = None, hlen = 1, raw_data = None, status = ''):
#        if not htype:
#            htype = self.TYPE
#        if raw_data:
#            Header.__init__(self, htype, hlen, raw_data)
#        else:
#            self.status = status
#
#    def parse(self):
#        """Parse data"""
#        self.lastsave = time.gmtime(unpack('=i', self.data)[0])
#
#    def __repr__(self):
#        return "LastSave" + Header.__repr__(self)
#
#    def __str__(self):
#        return "LastSave(%r)" % time.strftime("%a, %d %b %Y %H:%M:%S +0000", self.lastsave)
#
#    def serial(self):
#        return makedatetime(self.lastsave)

# Header(6,19,'Password Safe V3.23'),
class LastSaveAppHeader(Header):
    """ What app performed the last save
lastSaveApp        string        Last saved by this app
    """
    TYPE = 0x06

    def __init__(self, htype = None, hlen = 1, raw_data = None, lastSaveApp = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.lastSaveApp = lastSaveApp

    def parse(self):
        """Parse data"""
        self.lastSaveApp = self.data

    def __repr__(self):
        return "LastSaveApp" + Header.__repr__(self)

    def __str__(self):
        return "LastSaveAppHeader=%r" % self.lastSaveApp

    def serial(self):
        return self.lastSaveApp

# Header(7,6,'owenst'),
class LastSaveUserHeader(Header):
    """ User who last saved the DB. 
username    string        
    """
    TYPE = 0x07

    def __init__(self, htype = None, hlen = 1, raw_data = None, username = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.username = username

    def parse(self):
        """Parse data"""
        self.username = self.data

    def __repr__(self):
        return "LastSaveUser" + Header.__repr__(self)

    def __str__(self):
        return "LastSaveUserHeader(%r)" % self.username

    def serial(self):
        return self.username

# Header(8,15,'SOMEHOSTNAME'),
class LastSaveHostHeader(Header):
    """ Host that last saved the DB 
hostname    string        
    """
    TYPE = 0x08

    def __init__(self, htype = None, hlen = 1, raw_data = None, hostname = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.hostname = hostname

    def parse(self):
        """Parse data"""
        self.hostname = self.data

    def __repr__(self):
        return "LastSaveHost" + Header.__repr__(self)

    def __str__(self):
        return "LastSaveHostHeader(%r)" % self.hostname

    def serial(self):
        return self.hostname

class DBNameHeader(Header):
    """ Name of the database
dbName        String
    """
    TYPE = 0x09

    def __init__(self, htype = None, hlen = 1, raw_data = None, dbName = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.dbName = dbName

    def parse(self):
        """Parse data"""
        self.dbName = self.data

    def __repr__(self):
        return "DBName" + Header.__repr__(self)

    def __str__(self):
        return "DBNameHeader(%r)" % self.dbName

    def serial(self):
        return self.dbName
    
class DBDescHeader(Header):
    """ Description of the database
dbDesc        String
    """
    TYPE = 0x0a

    def __init__(self, htype = None, hlen = 1, raw_data = None, dbDesc = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.dbDesc = dbDesc

    def parse(self):
        """Parse data"""
        self.dbDesc = self.data

    def __repr__(self):
        return "DBDesc" + Header.__repr__(self)

    def __str__(self):
        return "DBDescHeader(%r)" % self.dbDesc

    def serial(self):
        return self.dbDesc

# FIXME: Finish this
class DBFiltersHeader(Header):
    """ Description of the database
dbDesc        String
Specfic filters for this database.  This is the text equivalent to
the XML export of the filters as defined by the filter schema. The text 
'image' has no 'print formatting' e.g. tabs and carraige return/line feeds,
since XML processing does not require this. This field was introduced in 
format version 0x0305.
    """
    TYPE = 0x0b

    def __init__(self, htype = None, hlen = 1, raw_data = None, dbDesc = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.dbDesc = dbDesc

    def parse(self):
        """Parse data"""
        self.dbDesc = self.data

    def __repr__(self):
        return "DBFilters" + Header.__repr__(self)

    def __str__(self):
        return "DBFiltersHeader(%r)" % self.dbDesc

    def serial(self):
        return self.dbDesc
    
# TODO: Figure out what "reserved" headers are used for in other apps

# TODO: Fill this in once we have something to test against
# FIXME: Finish this 
class RecentEntriesHeader(Header):
    """ Description of the database
recentEntries        List of UUIDs

A list of the UUIDs (32 hex character representation of the 16 byte field)
of the recently used entries, prefixed by a 2 hex character representation
of the number of these entries (right justified and left filled with zeroes).
The size of the number of entries field gives a maximum number of entries of 255,
however the GUI may impose further restrictions e.g. Windows MFC UI limits this
to 25. The first entry is the most recent entry accessed. This field was
introduced in format version 0x0307.
    """
    TYPE = 0x0f

    def __init__(self, htype = None, hlen = 1, raw_data = None, recentEntries = []):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            self.recentEntries = recentEntries

    def parse(self):
        """Parse data"""
        self.recentEntries = []

    def __repr__(self):
        return "RecentEntries" + Header.__repr__(self)

    def __str__(self):
        return "RecentEntriesHeader(%r)" % self.recentEntries

    def serial(self):
        return self.dbDesc    

class EOFHeader(Header):
    """End of headers
>>> x=EOFHeader(255,0,'\x00\x00\x00\x00\xff\xbc_AP\x10\xf19\xae\xe99g')
>>> repr(x)
"EOFHeader(255,0,'\\x00\\x00\\x00\\x00\\xff\\xbc_AP\\x10\\xf19\\xae\\xe99g')"
>>> str(x)
'EOF'
>>> x.serial()
''

    """
    TYPE = 0xff
    data = ''
    def __init__(self, htype = None, hlen = 0, raw_data = ''):
        if not htype:
            htype = self.TYPE
        if raw_data:
            Header.__init__(self, htype, hlen, raw_data)
        else:
            pass

    def __repr__(self):
        return "EOF" + Header.__repr__(self)

    def __str__(self):
        return "EOF"

def Create_Header(fetchblock_f):
    """Returns a header object. Uses fetchblock_f to read a 16 byte chunk of data
    fetchblock_f(number of blocks)
    """
    firstblock = fetchblock_f(1)
    log.debug("Header of header: %s" % repr(firstblock[:5]))
    (rlen, rtype) = unpack('=lc', firstblock[:5])
    rtype = ord(rtype)
    data = firstblock[5:]
    log.debug("Rtype: %s Len: %s" % (rtype, rlen))
    if rlen > len(data):
        data += fetchblock_f(((rlen - len(data) - 1) / 16) + 1)
    assert rlen <= len(data)
    # TODO: Clean up header add back
    data = firstblock[:5] + data
    if headers.has_key(rtype):
        return headers[rtype](rtype, rlen, data)
    else:
        # Unknown header
        return Header(rtype, rlen, data)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
    
