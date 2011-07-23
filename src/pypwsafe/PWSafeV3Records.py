#!/usr/bin/env python
# -*- coding: latin-1 -*-
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
"""Record and record properity objects

"""

from struct import unpack, pack
import calendar, time
import logging, logging.config
from errors import *
import os
from uuid import UUID, uuid4
#logging.config.fileConfig('/etc/mss/psafe_log.conf')
psafe_logger = logging.getLogger("psafe.lib.record")
psafe_logger.debug('initing')

class Record(object):
    """Represents a psafe3 record
    Container item: Name of properity
    Attrs
    records        [RecordProp]        List of properities
    lk        {TypeName:RecordProp}

    """

    def __init__(self, fetchblock_f = None):
        psafe_logger.debug('Creating record object')
        self.records = []
        self.lk = {}
        if fetchblock_f:
            psafe_logger.debug("Creating from existing data")
            rcd = Create_Prop(fetchblock_f)
            psafe_logger.debug("Creating record %s" % repr(rcd))
            self.records.append(rcd)
            self.lk[rcd.rNAME] = rcd
            while type(rcd) != EOERecordProp:
                rcd = Create_Prop(fetchblock_f)
                psafe_logger.debug("Creating record %s" % repr(rcd))
                self.records.append(rcd)
                self.lk[rcd.rNAME] = rcd
            psafe_logger.debug("Created all records. ")
        else:
            psafe_logger.debug("Creating blank object")
            # Create the UUID object
            self._if_noitem(UUIDRecordProp.rNAME)
            # Create the EOE object. This must happen last and can't use the if_noitem because it may
            # insert somewhere besides the end. 
            eoe = EOERecordProp()
            self.records.append(eoe)
            self.lk[eoe.rNAME] = eoe
        psafe_logger.debug('Created record object. ')

    def __getitem__(self, key):
        self._if_noitem(key)
        return self.lk[key].get()

    def __setitem__(self, key, val):
        self._if_noitem(key)
        # atm we are just updating our lk record
        self.lk[key].set(val)

    def _if_noitem(self, item):
        """If an item isn't in our key store, create it. """
        if not self.lk.has_key(item):
            for i in RecordPropTypes.values():
                if i.rNAME == item:
                    r = i()
                    self.lk[item] = r
                    self.records.insert(0, r)

    def __iter__(self):
        return self.lk.__iter__()

    def __repr__(self):
        ret = ''
        for i in self:
            ret += repr(self[i]) + "\n"
        return ret[:-1]

    def __str__(self):
        ret = ''
        for i in self.lk.keys():
            #print str(self.lk[i])

            ret += str(self.lk[i]) + "\n"
        return ret[:-1]

    def __len__(self):
        return len(self.records)

    def hmac_data(self):
        """Returns the data required for the "broken" hmac in psafe3. See bug 1812081. """
        ret = ''
        for i in self.records:
            # the data field has the data minus the padding
            #if i.serial()!=i.data:
            #    psafe_logger.warn('Serial != data for class %s. s: %s d: %s'%(repr(i.__class__),repr(i.serial()),repr(i.data)))
            ret += i.serial()
        return ret

    def serialiaze(self):
        """ """
        ret = ''
        for r in self.records:
            ret += r.serialiaze()
        return ret

RecordPropTypes = {}

class _RecordPropType(type):
    def __init__(cls, name, bases, dct):
        super(_RecordPropType, cls).__init__(name, bases, dct)
        # Skip any where rType is none, such as the base class
        if cls.rTYPE:
            RecordPropTypes[cls.rTYPE] = cls

#     Record Prop
class RecordProp(object):
    """A single properity of a psafe3 record. This represents an unknown type or is overridden by records of a known type.
    rTYPE        int        Properity type. May be null.
    rNAME        string        Code name of properity type.
    type        int        Prop type.
    len        int        Length, in bytes, of data
    raw_data    string        Record data including padding and headers
    data        string        Record data minus headers and padding
    """
    # Auto-register all declared classes
    __metaclass__ = _RecordPropType
    
    rTYPE = None
    rNAME = "Unknown"

    def __init__(self, ptype, plen, pdata):
        self.type = ptype
        if self.rTYPE:
            assert self.rTYPE == ptype
        else:
            self.rTYPE = ptype
        self.len = plen
        self.raw_data = pdata
        self.data = pdata[5:(plen + 5)]
        psafe_logger.debug('Created psafe record prop with rTYPE of %s. Class %s', repr(self.rTYPE), repr(self.__class__))
        self.parse()
        if self.rNAME == "Unknown":
            psafe_logger.debug('Created psafe record prop of unknown type. rType: %s rLen: %s Data: %s Raw: %s', repr(ptype), repr(plen), repr(self.data), repr(self.raw_data))
        else:
            psafe_logger.debug('Created psafe record prop of known type. rType: %s rLen: %s Data: %s Raw: %s', repr(ptype), repr(plen), repr(self.data), repr(self.raw_data))

    def parse(self):
        """Override me. Called on init to parse received data. """
        pass

    def __repr__(self):
        s = self.serial()
        return "RecordProp(%s,%d,%s)" % (hex(self.type), len(s), repr(s))

    def __str__(self):
        return self.__repr__()

    def get(self):
        return self.data

    def set(self, value):
        self.data = value

    def _rand_char(self):
        """Returns a random char"""
        return os.urandom(1)

    def _pad(self, data):
        """ Pad out data to 16 bytes """
        add_data = 16 - len(data) % 16
        if add_data == 16:
            add_data = 0
        padding = ''
        for i in xrange(0, add_data):
            padding += self._rand_char()
        assert add_data != 16
        assert len(padding) == add_data
        assert len(data + padding) % 16 == 0
        return data + padding

    def serial(self):
        """Returns the raw data blocks to generate this object 
        EXCLUDING TYPE+LEN!"""
        #psafe_logger.debug('Serial to %s',repr(self.data))
        return self.data

    def serialiaze(self):
        """Returns the raw data blocks to generate this object. """
        serial = self.serial()
        header = pack('=lc', len(serial), chr(self.rTYPE))
        padded = self._pad(header + serial)
        psafe_logger.debug("Padded output %s" % repr(padded))
        return padded

class UUIDRecordProp(RecordProp):
    """Record's unique id
    uuid        uuid.UUID
>>> x=UUIDRecordProp(0x1,16,'\x10\x00\x00\x00\x01\xfa@\xbd\x1f \xf5B\xf5\x88v#\xe4\x08\xae\x8a\xa1@\x16[\xfb\x8c\x87mq\xf70[')
>>> repr(x)
"UUIDRecordProp(0x1,16,'\\x10\\x00\\x00\\x00\\x01\\xfa@\\xbd\\x1f \\xf5B\\xf5\\x88v#\\xe4\\x08\\xae\\x8a\\xa1@\\x16[\\xfb\\x8c\\x87mq\\xf70[')"
>>> str(x)
'UUID=fa40bd1f-20f5-42f5-8876-23e408ae8aa1'
>>> x.serial()
'\xfa@\xbd\x1f \xf5B\xf5\x88v#\xe4\x08\xae\x8a\xa1'
    """
    rTYPE = 0x01
    rNAME = 'UUID'
    def __init__(self, ptype = None, plen = 16, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.uuid = uuid4()
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.uuid = UUID(bytes = unpack('=16s', self.data)[0])

    def __repr__(self):
        return "UUID" + RecordProp.__repr__(self)

    def __str__(self):
        return "UUID=%s" % str(self.uuid)

    def get(self):
        return self.uuid

    def set(self, value):
        """Accepts a UUID object or a hex string
        """
        if type(value) == UUID:
            self.uuid = value
        else:
            self.uuid = UUID(fields = value)

    def serial(self):
        #psafe_logger.debug("Serial to %s",repr(pack('=16s',str(self.uuid.bytes))))
        return pack('=16s', str(self.uuid.bytes))

class GroupRecordProp(RecordProp):
    """Record's Group
    group_str    string        Raw group string
    group        [string]    List of the groups. First entry is the top level group.
>>> x=GroupRecordProp(0x2,7,'\x07\x00\x00\x00\x02Group 0\x11"\xf1\x84')
>>> str(x)
"Group: 'Group 0'"
>>> repr(x)
'GroupRecordProp(0x2,7,\'\\x07\\x00\\x00\\x00\\x02Group 0\\x11"\\xf1\\x84\')'
>>> x.get()
['Group 0']
>>> x.serial()
'\x07\x00\x00\x00\x02Group 0'
    """
    rTYPE = 0x02
    rNAME = 'Group'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.group = []
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.group_str = self.data
        self.group = self.group_str.split('.')

    def __repr__(self):
        return "Group" + RecordProp.__repr__(self)

    def __str__(self):
        return "Group: %s" % repr(self.group_str)

    def get(self):
        return self.group

    def set(self, value):
        self.group = value

    def serial(self):
        self.group_str = '.'.join(self.group)
        #psafe_logger.debug("Serial to %s Data %s"%(repr(self.group_str),repr(self.data)))
        return self.group_str

class TitleRecordProp(RecordProp):
    """Record's title
    title        string        Title
>>> x=TitleRecordProp(0x3,7,'\x07\x00\x00\x00\x03Title 0\xd5\xed\xf5l')
>>> str(x)
"Title='Title 0'"
>>> repr(x)
"TitleRecordProp(0x3,7,'\\x07\\x00\\x00\\x00\\x03Title 0\\xd5\\xed\\xf5l')"
>>> x.serial()
'Title 0'
>>> x.get()
'Title 0'

    """
    rTYPE = 0x03
    rNAME = 'Title'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.title = ''
            pdata = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.title = self.data[:self.len]

    def __repr__(self):
        return "Title" + RecordProp.__repr__(self)

    def __str__(self):
        return "Title=" + repr(self.title)

    def get(self):
        return self.title

    def set(self, value):
        self.title = str(value)

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(self.title),repr(self.data)))
        return self.title

class UsernameRecordProp(RecordProp):
    """Record's username
    username    string        ...
>>> x=UsernameRecordProp(0x4,9,'\t\x00\x00\x00\x04username0\x06\xfb')
>>> str(x)
"Username='username0'"
>>> repr(x)
"UsernameRecordProp(0x4,9,'\\t\\x00\\x00\\x00\\x04username0\\x06\\xfb')"
>>> x.get()
'username0'
>>> x.serial()
'username0'
    """
    rTYPE = 0x04
    rNAME = 'Username'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            pdata = ''
            self.username = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.username = self.data[:self.len]

    def __repr__(self):
        return "Username" + RecordProp.__repr__(self)

    def __str__(self):
        return "Username=" + repr(self.username)

    def get(self):
        return self.username

    def set(self, value):
        self.username = value

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(self.username),repr(self.data)))
        return self.username

class NotesRecordProp(RecordProp):
    """Record notes
    notes        string        ...
>>> x=NotesRecordProp(0x5,10,'\n\x00\x00\x00\x05more notes\x8c')
>>> str(x)
"Notes='more notes'"
>>> repr(x)
"NotesRecordProp(0x5,10,'\\n\\x00\\x00\\x00\\x05more notes\\x8c')"
>>> x.get()
'more notes'
>>> x.serial()
'more notes'

    """
    rTYPE = 0x05
    rNAME = 'Notes'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.notes = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.notes = self.data[:self.len]

    def __repr__(self):
        return "Notes" + RecordProp.__repr__(self)

    def __str__(self):
        return "Notes=" + repr(self.notes)

    def get(self):
        return self.notes

    def set(self, value):
        self.notes = str(value)

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(self.notes),repr(self.data)))
        return self.notes

class PasswordRecordProp(RecordProp):
    """Record's  password
    password    string        ...
>>> x=PasswordRecordProp(0x6,9,'\t\x00\x00\x00\x06password0d\xe7')
>>> str(x)
"Password='password0'"
>>> repr(x)
"PasswordRecordProp(0x6,9,'\\t\\x00\\x00\\x00\\x06password0d\\xe7')"
>>> x.get()
'password0'
>>> x.serial()
'password0'
    """
    rTYPE = 0x06
    rNAME = 'Password'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.password = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    # TODO: Add handling for links. See formatv3 3.3[3]
    def parse(self):
        self.password = self.data[:self.len]

    def __repr__(self):
        return "Password" + RecordProp.__repr__(self)

    def __str__(self):
        return "Password=" + repr(self.password)

    def get(self):
        return self.password

    def set(self, value):
        self.password = str(value)

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(self.password),repr(self.data)))
        return self.password

class CreationTimeRecordProp(RecordProp):
    """Record's  ctime
    password    string        ...
>>> x=CreationTimeRecordProp(0x7,4,'\x04\x00\x00\x00\x07\xda\x17;G\x86\xd5\x7f\xd2\x1a\xeb\xc5')
>>> x.serial()
'\xda\x17;G'
>>> x.get()
(2007, 11, 14, 15, 44, 26, 2, 318, 0)
>>> str(x)
'CTime=Wed, 14 Nov 2007 15:44:26 +0000'
>>> repr(x)
"CreationTimeRecordProp(0x7,4,'\\x04\\x00\\x00\\x00\\x07\\xda\\x17;G\\x86\\xd5\\x7f\\xd2\\x1a\\xeb\\xc5')"

    """
    rTYPE = 0x07
    rNAME = 'ctime'

    def __init__(self, ptype = None, plen = 4, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.dt = time.gmtime()
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.dt = parsedatetime(self.data[:self.len])

    def __repr__(self):
        return "CreationTime" + RecordProp.__repr__(self)

    def __str__(self):
        return "CTime=" + time.strftime("%a, %d %b %Y %H:%M:%S +0000", self.dt)

    def get(self):
        return self.dt

    def set(self, value):
        self.dt = value

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(makedatetime(self.dt)),repr(self.data)))
        return makedatetime(self.dt)

class ModTimeRecordProp(RecordProp):
    """Record's  mtime
    password    string        ...
>>> x=ModTimeRecordProp(0x8,4,'\x04\x00\x00\x00\x08\xd6\x8apI\xd2\xec\xc0_\xfb\x994')
>>> x.serial()
'\xd6\x8apI'
>>> x.get()
(2009, 1, 16, 13, 25, 42, 4, 16, 0)
>>> str(x)
'MTime=Fri, 16 Jan 2009 13:25:42 +0000'
>>> repr(x)
"ModTimeRecordProp(0x8,4,'\\x04\\x00\\x00\\x00\\x08\\xd6\\x8apI\\xd2\\xec\\xc0_\\xfb\\x994')"
    """
    rTYPE = 0x08
    rNAME = 'mtime'

    def __init__(self, ptype = None, plen = 4, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.dt = time.gmtime()
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.dt = parsedatetime(self.data[:self.len])

    def __repr__(self):
        return 'ModTime' + RecordProp.__repr__(self)

    def __str__(self):
        return "MTime=" + time.strftime("%a, %d %b %Y %H:%M:%S +0000", self.dt)

    def get(self):
        return self.dt

    def set(self, value):
        self.dt = value

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(makedatetime(self.dt)),repr(self.data)))
        return makedatetime(self.dt)

class LastAccessTimeRecordProp(RecordProp):
    """Record's  ctime
    password    string        ...
   
>>> x=LastAccessTimeRecordProp(0x9,4,'\x04\x00\x00\x00\t\xe4\x9fpI\xb2H\x860\x7f|\xf8')
>>> str(x)
'LastAccess=Fri, 16 Jan 2009 14:55:32 +0000'
>>> repr(x)
"LastAccessTimeRecordProp(0x9,4,'\\x04\\x00\\x00\\x00\\t\\xe4\\x9fpI\\xb2H\\x860\\x7f|\\xf8')"
>>> x.get()
(2009, 1, 16, 14, 55, 32, 4, 16, 0)
>>> x.serial()
'\xe4\x9fpI'
 
    """
    rTYPE = 0x09
    rNAME = 'LastAccess'

    def __init__(self, ptype = None, plen = 4, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.dt = time.gmtime()
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.dt = parsedatetime(self.data[:self.len])

    def __repr__(self):
        return 'LastAccessTime' + RecordProp.__repr__(self)

    def __str__(self):
        return self.rNAME + "=" + time.strftime("%a, %d %b %Y %H:%M:%S +0000", self.dt)

    def get(self):
        return self.dt

    def set(self, value):
        self.dt = value

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(makedatetime(self.dt)),repr(self.data)))
        return makedatetime(self.dt)

class PasswordExpiryTimeRecordProp(RecordProp):
    """Record's  experation time
    password    string        ...
>>> x=PasswordExpiryTimeRecordProp(0xa,4,'\x04\x00\x00\x00\n""wIy\xb8La\x8fOu')
>>> str(x)
'PasswordExpiry=Wed, 21 Jan 2009 13:24:50 +0000'
>>> repr(x)
'PasswordExpiryTimeRecordProp(0xa,4,\'\\x04\\x00\\x00\\x00\\n""wIy\\xb8La\\x8fOu\')'
>>> x.get()
(2009, 1, 21, 13, 24, 50, 2, 21, 0)
>>> x.serial()
'""wI'
    """
    rTYPE = 0x0a
    rNAME = 'PasswordExpiry'

    def __init__(self, ptype = None, plen = 4, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.dt = time.gmtime(0)
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.dt = parsedatetime(self.data[:self.len])

    def __repr__(self):
        return 'PasswordExpiryTime' + RecordProp.__repr__(self)

    def __str__(self):
        return self.rNAME + "=" + time.strftime("%a, %d %b %Y %H:%M:%S +0000", self.dt)

    def get(self):
        return self.dt

    def set(self, value):
        self.dt = value

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(makedatetime(self.dt)),repr(self.data)))
        return makedatetime(self.dt)

class LastModificationTimeRecordProp(RecordProp):
    """Record's  experation time
    password    string        ...
>>> x=LastModificationTimeRecordProp(0xc,4,'\x04\x00\x00\x00\x0c\xd6\x8apI\x14\xff\xb1?\x80q\xeb')
>>> str(x)
'LastModification=Fri, 16 Jan 2009 13:25:42 +0000'
>>> repr(x)
"LastModificationTimeRecordProp(0xc,4,'\\x04\\x00\\x00\\x00\\x0c\\xd6\\x8apI\\x14\\xff\\xb1?\\x80q\\xeb')"
>>> x.get()
(2009, 1, 16, 13, 25, 42, 4, 16, 0)
>>> x.serial()
'\xd6\x8apI'

    """
    rTYPE = 0x0c
    rNAME = 'LastModification'

    def __init__(self, ptype = None, plen = 4, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.dt = time.gmtime()
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.dt = parsedatetime(self.data[:self.len])

    def __repr__(self):
        return 'LastModificationTime' + RecordProp.__repr__(self)

    def __str__(self):
        return self.rNAME + "=" + time.strftime("%a, %d %b %Y %H:%M:%S +0000", self.dt)

    def get(self):
        return self.dt

    def set(self, value):
        self.dt = value

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(makedatetime(self.dt)),repr(self.data)))
        return makedatetime(self.dt)

class URLRecordProp(RecordProp):
    """Record's URL
    title        string        Title
>>> x=URLRecordProp(0xd,5,'\x05\x00\x00\x00\ra url\xaczf\xca:2')
>>> repr(x)
"URLRecordProp(0xd,5,'\\x05\\x00\\x00\\x00\\ra url\\xaczf\\xca:2')"
>>> str(x)
"URL='a url'"
>>> x.get()
'a url'
>>> x.serial()
'a url'
    """
    rTYPE = 0x0d
    rNAME = 'URL'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.url = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.url = self.data[:self.len]

    def __repr__(self):
        return 'URL' + RecordProp.__repr__(self)

    def __str__(self):
        return self.rNAME + "=" + repr(self.url)

    def get(self):
        return self.url

    def set(self, value):
        self.url = str(value)

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(self.url),repr(self.data)))
        return self.url

class AutotypeRecordProp(RecordProp):
    """Record's title
    title        string        Title
>>> x=AutotypeRecordProp(0xe,12,'\x0c\x00\x00\x00\x0emeh autotype-Ch\xcd\x99$i\xc0\xb7\x87\x0f\x0bN,\x05')
>>> repr(x)
"AutotypeRecordProp(0xe,12,'\\x0c\\x00\\x00\\x00\\x0emeh autotype-Ch\\xcd\\x99$i\\xc0\\xb7\\x87\\x0f\\x0bN,\\x05')"
>>> str(x)
"AutoType='meh autotype'"
>>> x.get()
'meh autotype'
>>> x.serial()
'meh autotype'

    """
    rTYPE = 0x0e
    rNAME = 'Autotype'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.autotype = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.autotype = self.data[:self.len]

    def __repr__(self):
        return "Autotype" + RecordProp.__repr__(self)

    def __str__(self):
        return "AutoType=" + repr(self.autotype)

    def get(self):
        return self.autotype

    def set(self, value):
        self.autotype = str(value)

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(self.autotype),repr(self.data)))
        return self.autotype

class PasswordHistoryRecordProp(RecordProp):
    """Record's old passwords
Password History is an optional record. If it exists, it stores the
creation times and values of the last few passwords used in the current
entry, in the following format:
    "fmmnnTLPTLP...TLP"
where:
    f  = {0,1} if password history is on/off
    mm = 2 hexadecimal digits max size of history list (i.e. max = 255)
    nn = 2 hexadecimal digits current size of history list
    T  = Time password was set (time_t written out in %08x)
    L  = 4 hexadecimal digit password length (in TCHAR)
    P  = Password

    raw_data        string        Just my data
    enabled        bool            True if we are keeping password history
    history            [time,pass]    Password history
    maxsize        int            Max size of history
    zerohack        bool           True if there is a trailing 00. Used
                                   to make sure the hmac calcs right on
                                   certian records with no history. 
                                   ie does 0ff0000 instead of 0ff00. 
                                   Update: See bug 2529736. 

>>> x=PasswordHistoryRecordProp(0xf,72,'H\x00\x00\x00\x0f1ff03473b17da000blaskdjflkxn48d98049000claskdjflkxnd49708a980008N0Y2Dkir\x9b\xa4\xb5')
>>> x.serial()
'1ff03473b17da000blaskdjflkxn48d98049000claskdjflkxnd49708a980008N0Y2Dkir'
>>> repr(x)
"PasswordHistoryRecordProp(0xf,72,'H\\x00\\x00\\x00\\x0f1ff03473b17da000blaskdjflkxn48d98049000claskdjflkxnd49708a980008N0Y2Dkir\\x9b\\xa4\\xb5')"
>>> str(x)
'PasswordHistory(Enabled: True\nMax size: 255\nCur Size: 3\nCreated: Wed, 14 Nov 2007 15:44:26 +0000\nPassword: laskdjflkxn\nCreated: Tue, 23 Sep 2008 23:48:25 +0000\nPassword: laskdjflkxnd\nCreated: Fri, 16 Jan 2009 13:24:40 +0000\nPassword: N0Y2Dkir\n)'
>>> x.get()
{'maxsize': 255, 'enable': True, 'history': {'Tue, 23 Sep 2008 23:48:25 +0000': 'laskdjflkxnd', 'Fri, 16 Jan 2009 13:24:40 +0000': 'N0Y2Dkir', 'Wed, 14 Nov 2007 15:44:26 +0000': 'laskdjflkxn'}, 'currentsize': 3}

    """
    rTYPE = 0x0f
    rNAME = 'PasswordHistory'

    def __init__(self, ptype = None, plen = 0, pdata = None, enabled = 0, maxsize = 255):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.enabled = enabled
            self.maxsize = maxsize
            self.history = []
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def serial(self):
        ret = ''
        if self.enabled:
            ret += "1"
        else:
            ret += "0"
        ret += "%02x" % self.maxsize
        ret += "%02x" % len(self.history)
        psafe_logger.debug("Pre-passwords %s" % repr(ret))
        for (tm, passwd) in self.history:
            ret += "%08x" % calendar.timegm(tm)
            ret += "%04x" % len(passwd)
            ret += passwd
            psafe_logger.debug("Post-add password %s" % repr(ret))
        if len(self.history) == 0 and self.zerohack:
            ret += "00"
        #psafe_logger.debug("Serial to %s data %s"%(repr(ret),repr(self.data)))
        return ret

    def parse(self):
        if len(self.data) == 7:
            self.zerohack = True
        else:
            self.zerohack = False
        if len(self.data) > 0:
            # Enabled/disabled
            if self.data[0] == "0":
                self.enabled = False
            elif self.data[0] == "1":
                self.enabled = True
            else:
                raise PropParsingError, "Invalid enabled/disabled flag %s" % repr(self.data[0])
            psafe_logger.debug("Set password history to %s", repr(self.enabled))
            # Max size of hist list
            try:
                self.maxsize = int(self.data[1:3], 16)
            except ValueError:
                raise PropParsingError, "Invalid maxsize type %s" % repr(self.data[1:3])
            if self.maxsize < 0 or self.maxsize > 255:
                raise PropParsingError, "Invalid maxsize value %s" % repr(self.data[1:3])
            psafe_logger.debug("Set password history max size to %d", self.maxsize)
            # Current size of hist list
            try:
                self._cursize = int(self.data[3:5], 16)
            except ValueError:
                raise PropParsingError, "Invalid cursize type %s" % repr(self.data[3:5])
            if self._cursize < 0 or self._cursize > 255:
                raise PropParsingError, "Invalid cursize value %s" % repr(self.data[3:5])
            psafe_logger.debug("Set current size of password history to %d", self._cursize)
            # FIXME: Should this end at self.len? 
            try:
                data = self.data[5:]
                self.history = []
                i = self._cursize
                while len(data) > 12 and i > 0:
                    i -= 1
                    # Split out the data
                    tm_raw = data[:8]
                    len_raw = data[8:12]
                    data = data[12:]
                    # Parse known data
                    # TODO: Check for errors
                    tm = time.gmtime(int(tm_raw, 16))
                    len_real = int(len_raw, 16)
                    password = data[:len_real]
                    data = data[len_real:]
                    self.history.append((tm, password))
            except ValueError:
                raise PropParsingError, "Error parsing password history"
            assert self._cursize == len(self.history)

    def __repr__(self):
        return self.rNAME + RecordProp.__repr__(self)

    def __str__(self):
        ret = self.rNAME + "("
        ret += "Enabled: %s\n" % repr(self.enabled)
        ret += "Max size: %s\n" % repr(self.maxsize)
        ret += "Cur Size: %s\n" % repr(len(self.history))
        for (createddt, passwd) in self.history:
            ret += "Created: %s\n" % time.strftime("%a, %d %b %Y %H:%M:%S +0000", createddt)
            ret += "Password: %s\n" % passwd
        ret += ")"
        return ret

    def get(self):
        hist = {}
        for (createddt, passwd) in self.history:
            #used to return time.strftime("%a, %d %b %Y %H:%M:%S +0000",createddt)
            hist[createddt] = passwd
        return dict(
            enable = self.enabled
            , maxsize = self.maxsize
            , currentsize = len(self.history)
            , history = hist
            )

    def set(self, value):
        self.enabled = value['enabled']
        self.maxsize = value['maxsize']
        self.history = []
        for (dt, passwd) in value['history']:
            self.history.append((dt, passwd))

class PasswordPolicyRecordProp(RecordProp):
    """Record's title
    This field allows a specific Password Policy per entry.  The format is:
    ffffnnnllluuudddsss"
where:
     ffff = 4 hexadecimal digits representing the following flags
        UseLowercase =      0x8000  - can have a minimum length
        UseUppercase =      0x4000  - can have a minimum length
        UseDigits =         0x2000  - can have a minimum length
        UseSymbols =        0x1000  - can have a minimum length
        UseHexDigits =      0x0800 (if set, then no other flags can be set)
        UseEasyVision =     0x0400
        MakePronounceable = 0x0200
        Unused              0x01ff
    nnn  = 3 hexadecimal digits password total length
    lll  = 3 hexadecimal digits password minimum number of lowercase characters
    uuu  = 3 hexadecimal digits password minimum number of uppercase characters
    ddd  = 3 hexadecimal digits password minimum number of digit characters
    sss  = 3 hexadecimal digits password minimum number of symbol characters

>>> x=PasswordPolicyRecordProp(0x10,19,'\x13\x00\x00\x00\x10f000010004001005002n_S-\x84r\xeb\xe4')
>>> str(x)
'PasswordPolicy=\nUse Lowercase: True\nUse Uppercase: True\nUse Digits: True\nUse Symbols: True\nUse Hex: False\nUse Easy Version: False\nMake Pronounceable: False\nTotal Length: 16\nMin Lowercase: 4\nMin Uppercase: 1\nMin Digits: 5\nMin Symbols: 2'
>>> repr(x)
"PasswordPolicyRecordProp(0x10,19,'\\x13\\x00\\x00\\x00\\x10f000010004001005002n_S-\\x84r\\xeb\\xe4')"
>>> x.get()
{'UseEasy': False, 'MinSymbols': 2, 'MinDigits': 5, 'MakePronounceable': False, 'MinUpper': 1, 'UseHex': False, 'TotalLen': 16, 'UseDigits': True, 'UseLower': True, 'UseSymbols': True, 'MinLower': 4, 'UseUpper': True}
>>> x.serial()
'b000010004001005002'
    """
    rTYPE = 0x10
    rNAME = 'PasswordPolicy'
    # A few constants
    USELOWERCASE = 0x8000
    USEUPPERCASE = 0x4000
    USEDIGITS = 0x2000
    USESYMBOLS = 0x1000
    USEHEXDIGITS = 0x0800
    USEEASYVERSION = 0x0400
    MAKEPRONOUNCEABLE = 0x0200
    UNUSED = 0x01ff

    def __init__(self
                 , ptype = None
                 , plen = 0
                 , pdata = None
                 , ttllen = 14
                 , minlow = 2
                 , minup = 2
                 , mindig = 2
                 , minsym = 2
                 , uselowercase = True
                 , useuppercase = True
                 , usedigits = True
                 , usesymbols = True
                 , usehex = False
                 , useeasy = False
                 , makepron = False
                 ):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.ttllen = ttllen
            self.minlow = minlow
            self.minup = minup
            self.mindig = mindig
            self.minsym = minsym
            self.uselowercase = uselowercase
            self.useuppercase = useuppercase
            self.usedigits = usedigits
            self.usesymbols = usesymbols
            self.usehex = usehex
            self.useeasy = useeasy
            self.makepron = makepron
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def serial(self):
        flags = 0
        if self.uselowercase:
            flags = flags | self.USELOWERCASE
        if self.useuppercase:
            flags = flags | self.USELOWERCASE
        if self.usedigits:
            flags = flags | self.USEDIGITS
        if self.usesymbols:
            flags = flags | self.USESYMBOLS
        if self.usehex:
            flags = flags | self.USEHEXDIGITS
        if self.useeasy:
            flags = flags | self.USEEASYVERSION
        if self.makepron:
            flags = flags | self.MAKEPRONOUNCEABLE
        ret = '%04x%03x%03x%03x%03x%03x' % (flags, self.ttllen, self.minlow, self.minup, self.mindig, self.minsym)
        #psafe_logger.debug("Serial to %s data %s"%(repr(ret),repr(self.data)))    
        return ret

    def parse(self):
        self.mydata = self.data[:self.len]
        policy = unpack('=4s3s3s3s3s3s', self.mydata)
        # str hex to int
        policy = [int(x, 16) for x in policy]
        (flags, self.ttllen, self.minlow, self.minup, self.mindig, self.minsym) = policy
        if flags & self.USELOWERCASE:
            self.uselowercase = True
        else:
            self.uselowercase = False
        if flags & self.USEUPPERCASE:
            self.useuppercase = True
        else:
            self.useuppercase = False
        if flags & self.USEDIGITS:
            self.usedigits = True
        else:
            self.usedigits = False
        if flags & self.USESYMBOLS:
            self.usesymbols = True
        else:
            self.usesymbols = False
        if flags & self.USEHEXDIGITS:
            self.usehex = True
        else:
            self.usehex = False
        if flags & self.USEEASYVERSION:
            self.useeasy = True
        else:
            self.useeasy = False
        if flags & self.MAKEPRONOUNCEABLE:
            self.makepron = True
        else:
            self.makepron = False
        psafe_logger.debug(str(self))

    def __repr__(self):
        return self.rNAME + RecordProp.__repr__(self)

    def __str__(self):
        ret = self.rNAME + "="
        ret += "\nUse Lowercase: " + str(self.uselowercase)
        ret += "\nUse Uppercase: " + str(self.useuppercase)
        ret += "\nUse Digits: " + str(self.usedigits)
        ret += "\nUse Symbols: " + str(self.usesymbols)
        ret += "\nUse Hex: " + str(self.usehex)
        ret += "\nUse Easy Version: " + str(self.useeasy)
        ret += "\nMake Pronounceable: " + str(self.makepron)
        ret += "\nTotal Length: " + str(self.ttllen)
        ret += "\nMin Lowercase: " + str(self.minlow)
        ret += "\nMin Uppercase: " + str(self.minup)
        ret += "\nMin Digits: " + str(self.mindig)
        ret += "\nMin Symbols: " + str(self.minsym)
        return ret

    def get(self):
        return dict(
            UseLower = self.uselowercase
            , UseUpper = self.useuppercase
            , UseDigits = self.usedigits
            , UseSymbols = self.usesymbols
            , UseHex = self.usehex
            , UseEasy = self.useeasy
            , MakePronounceable = self.makepron
            , TotalLen = self.ttllen
            , MinLower = self.minlow
            , MinUpper = self.minup
            , MinDigits = self.mindig
            , MinSymbols = self.minsym
       )

    def set(self, value):
        self.uselowercase = bool(value['UseLower'])
        self.useuppercase = bool(value['UseUpper'])
        self.usedigits = bool(value['UseDigits'])
        self.usesymbols = bool(value['UseSymbols'])
        self.usehex = bool(value['UseHex'])
        self.useeasy = bool(value['UseEasy'])
        self.makepron = bool(value['MakePronounceable'])
        self.ttllen = int(value['TotalLen'])
        self.minlow = int(value['MinLower'])
        self.minup = int(value['MinUpper'])
        self.mindig = int(value['MinDigits'])
        self.minsym = int(value['MinSymbols'])

class PasswordExpiryIntervalRecordProp(RecordProp):
    """Number of days before the password expires.
Password Expiry Interval, in days, before this password expires. Once set,
this value is used when the password is first generated and thereafter whenever
the password is changed, until this value is unset.  Valid values are 1-3650
corresponding to up to approximately 10 years.  A value of zero is equivalent to
this field not being set.

    ttl        string        Title
>>> x=PasswordExpiryIntervalRecordProp(0x11,4,'\x04\x00\x00\x00\x11\n\x00\x00\x00\xf1\xe9\xb1\xd0e\xd6h')
>>> repr(x)
"PasswordExpiryIntervalRecordProp(0x11,4,'\\x04\\x00\\x00\\x00\\x11\\n\\x00\\x00\\x00\\xf1\\xe9\\xb1\\xd0e\\xd6h')"
>>> str(x)
'PasswordExpiryInterval=10'
>>> x.get()
10
>>> x.serial()
'\n\x00\x00\x00'
    """
    rTYPE = 0x11
    rNAME = 'PasswordExpiryInterval'

    def __init__(self, ptype = None, plen = 4, pdata = None, ttl = 0):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.ttl = ttl
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.mydata = self.data[:self.len]
        self.ttl = int(unpack('=l', self.mydata)[0])

    def __repr__(self):
        return self.rNAME + RecordProp.__repr__(self)

    def __str__(self):
        return self.rNAME + "=" + repr(self.ttl)

    def get(self):
        return self.ttl

    def set(self, value):
        self.ttl = int(value)

    def serial(self):
        ret = pack('=l', self.ttl)
        #psafe_logger.debug("Serial to %s data %s"%(repr(ret),repr(self.data)))
        return ret

class RunCommandRecordProp(RecordProp):
    """Record's URL
    runCommand    string

    """
    rTYPE = 0x12
    rNAME = 'RunCommand'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.runCommand = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.runCommand = self.data[:self.len]

    def __repr__(self):
        return 'RunCommand' + RecordProp.__repr__(self)

    def __str__(self):
        return self.rNAME + "=" + repr(self.runCommand)

    def get(self):
        return self.runCommand

    def set(self, value):
        self.runCommand = str(value)

    def serial(self):
        #psafe_logger.debug("Serial to %s data %s"%(repr(self.url),repr(self.data)))
        return self.runCommand

class DoubleClickActionRecordProp(RecordProp):
    """ Double click action 
A two byte field contain the value of the Double-Click Action 'preference 
390    value' (0xff means use the current Application default):
391    Current 'preference values' are:
392        CopyPassword           0
393        ViewEdit               1
394        AutoType               2
395        Browse                 3
396        CopyNotes              4
397        CopyUsername           5
398        CopyPasswordMinimize   6
399        BrowsePlus             7


    """
    rTYPE = 0x13
    rNAME = 'DoubleClickAction'

    COPYPASSWORD = 0x00
    VIEWEDIT = 0x01
    AUTOTYPE = 0x02
    BROWSE = 0x03
    COPYNOTES = 0x04
    COPYUSERNAME = 0x05
    COPYPASSWORDMIN = 0x06
    BROWSEPLUS = 0x07
    DEFAULT = 0xff
    def __init__(self, ptype = None, plen = 4, pdata = None, action = DEFAULT):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            self.action = action
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def parse(self):
        self.mydata = self.data[:self.len]
        self.action = int(unpack('=l', self.mydata)[0])

    def __repr__(self):
        return self.rNAME + RecordProp.__repr__(self)

    def __str__(self):
        return self.rNAME + "=" + repr(self.action)

    def get(self):
        return self.action

    def set(self, value):
        self.action = int(value)

    def serial(self):
        ret = pack('=l', self.action)
        #psafe_logger.debug("Serial to %s data %s"%(repr(ret),repr(self.data)))
        return ret

class EOERecordProp(RecordProp):
    """End of entry

>>> x=EOERecordProp(0xff,0,'\x00\x00\x00\x00\xff\xb5\xce\xd9 =\xe99\x14\xc1.\xfe')
>>> repr(x)
"EOERecordProp(0xff,0,'\\x00\\x00\\x00\\x00\\xff\\xb5\\xce\\xd9 =\\xe99\\x14\\xc1.\\xfe')"
>>> str(x)
'End of Entry'
>>> x.get()
'EOE'
>>> x.serial()
'\x00\x00\x00\x00\xff\xb5\xce\xd9 =\xe99\x14\xc1.\xfe'
    """
    rTYPE = 0xff
    rNAME = 'EOE'

    def __init__(self, ptype = None, plen = 0, pdata = None):
        if not ptype:
            ptype = self.rTYPE
        assert ptype == self.rTYPE
        if not pdata:
            pdata = ''
        else:
            RecordProp.__init__(self, ptype, plen, pdata)

    def __repr__(self):
        return "EOE" + RecordProp.__repr__(self)

    def __str__(self):
        return "End of Entry"

    def get(self):
        return ''

    def set(self, value):
        raise ValueError, "Can't set data to the EOE record"

    def serial(self):
        return ''

def parsedatetime(data):
    """Takes in the raw psafev3 data for a time value and returns a date/time tuple"""
    return time.gmtime(unpack('=i', data)[0])

def makedatetime(dt):
    return pack('=i', calendar.timegm(dt))

def Create_Prop(fetchblock_f):
    """Returns a record properity. Uses fetchblock_f to read a 16 byte chunk of data
    fetchblock_f(number of blocks)
    """
    psafe_logger.debug('Create_Prop')
    firstblock = fetchblock_f(1)
    (rlen, rTYPE) = unpack('=lc', firstblock[:5])
    rTYPE = ord(rTYPE)
    psafe_logger.debug('rtype %s rlen %s' % (rTYPE, rlen))
    data = firstblock[5:]
    if rlen > len(data):
        data += fetchblock_f(((rlen - len(data) - 1) / 16) + 1)
    assert rlen <= len(data)
    #print "Creating records with %s"%repr((rTYPE,rlen,data,len(data)))
    # Lazy way to add the header data back
    # TODO: Clean up header add back
    data = firstblock[:5] + data
    if RecordPropTypes.has_key(rTYPE):
        try:
            return RecordPropTypes[rTYPE](rTYPE, rlen, data)
        except:
            psafe_logger.exception('Failed to create record prop')
            return RecordProp(rTYPE, rlen, data)
    else:
        # Unknown header
        psafe_logger.debug('Unknown header type %s' % repr(rTYPE))
        return RecordProp(rTYPE, rlen, data)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
