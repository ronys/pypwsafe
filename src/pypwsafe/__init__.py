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
""" Read & write Password Safe v3 files. 

@author: Paulson McIntyre <paul@gpmidi.net>
@license: GPLv2
@version: 0.1
"""
# Lets this lib work from both 2.4 and above
try:
    from hashlib import sha256_func #@UnresolvedImport
    from hashlib import sha256_mod #@UnresolvedImport
except:
    import Crypto.Hash.SHA256 as sha256_mod #@UnresolvedImport @Reimport
    from Crypto.Hash.SHA256 import new as sha256_func #@UnresolvedImport @Reimport
from mcrypt import MCRYPT #@UnresolvedImport
from hmac import new as HMAC
from PWSafeV3Headers import *
from PWSafeV3Records import *
from errors import *
import os, os.path
from struct import pack, unpack
import logging, logging.config
import socket

log = logging.getLogger("psafe.lib.init")
log.debug('initing')
from uuid import uuid4

def stretchkey(passwd, salt, count):
    """
    Stretch a key. H(pass+salt)
    @param passwd: The password being stretched
    @type passwd: string
    @param salt: Salt for the password. Should pre-provided random data. 
    @type salt: string
    @param count: The number of times to repeat the stretch function
    @type count: int   
    """
    assert count > 0
    # Hash once with both
    inithsh = sha256_func()
    inithsh.update(passwd)
    inithsh.update(salt)
    # Expecting it in binary form; NOT HEX FORM
    hsh = inithsh.digest()
    # Rehash
    for i in xrange(count):
        t = sha256_func()
        t.update(hsh)
        hsh = t.digest()
    return hsh

from struct import pack, unpack
class PWSafe3(object):
    """ A Password safe object. Allows read/write access to most header fields and records in a psafe object. 
    """
    
    filename = None
    """@ivar: Full path to pwsafe
    @type filename: string
    """
    
    password = None
    """@ivar: Passsafe password
    @type password: string
    """
    
    fl = None
    """@ivar: PWSafe file handle
    @type fl: File Handle
    """
    
    flfull = None
    """@ivar: Contents of pwsafe file
    @type flfull: string
    """
            
    pprime = None
    """@ivar: Stretched key used in B1 - B4
    @type pprime: string
    """
    
    enckey = None
    """@ivar: K; session key for main data block
    @type enckey: string
    """
    
    hshkey = None
    """@ivar: L; hmac key
    @type hshkey: string
    """
    
    records = None
    """@ivar: List of all records we have
    @type records: [Record,...]
    """
    
    hmacreq = None
    """@ivar: List of functions to run to generate hmac. Order matters when reading a file.
    @type hmacreq: function
    """
    
    hmac = None
    """@ivar: Originally its the hmac from the file. Should be updated when ever changes are made.
    @type hmac: string
    """
    
    mode = None
    """@ivar: Read only or read/write mode. "RO" for read-only or "RW" or read/write.  
    @type mode: string
    """
    
    iv = None
    """@ivar: Initialization vector used for CBC mode when encrypting / decrypting the header and records.
    @type iv: string[16]
    """ 
    
    def __init__(self, filename, password, mode = "RW"):
        """
        @param filename: The path to the Password Safe file. Will be created if it doesn't already exist. 
        @type filename: string
        @param password: The password to encrypt/decrypt the safe with. 
        @type password: string
        @param mode: Read only or read/write mode. "RO" for read-only or "RW" or read/write.  
        @type mode: string
        """   
        log.debug('Creating psafe %s' % repr(filename))
        self.locked = False
        psafe_exists = os.access(filename, os.F_OK)
        psafe_canwrite = os.access(filename, os.W_OK)
        psafe_canwritebase = os.access(os.path.dirname(filename), os.W_OK)
        psafe_canread = os.access(filename, os.R_OK)
        if psafe_exists and psafe_canread and not psafe_canwrite:
            log.debug("Opening RO")
            self.mode = "RO"
        elif psafe_exists and psafe_canread and psafe_canwrite and mode == "RW":
            log.debug("Opening RW")
            self.mode = "RW"
        elif psafe_exists and psafe_canread and psafe_canwrite and mode != "RW":
            log.debug("Opening RO")
            self.mode = "RO"
        elif not psafe_exists and psafe_canwritebase and mode == "RW":
            log.debug("Creating new psafe as RW")
            self.mode = "RW"
        elif not psafe_exists and psafe_canwrite and mode != "RW":
            log.warn("Asked to create a new psafe but mode is set to RO")
            raise AccessError, "Asked to create a new safe in RO mode"
        elif psafe_exists:
            log.warn("Can't read safe %s" % repr(filename))
            raise AccessError, "Can't read %s" % filename
        else:
            log.warn("Safe doesn't exist or can't read directory")
            raise AccessError, "No such safe %s" % filename
        if psafe_exists:            
            self.filename = filename
            log.debug("Loading existing safe from %r" % self.filename)
            self.fl = open(self.filename, 'rb')
            try:
                self.flfull = self.fl.read()
                log.debug("Full data len: %d" % len(self.flfull))
                self.password = str(password)
                # Read in file
                self.load()
            finally:
                self.fl.close()
        else:
            log.debug("New psafe")
            self.password = str(password)
            self.filename = filename
            # Init local vars
            # SALT
            self.salt = os.urandom(32)
            log.debug("Salt is %s" % repr(self.salt))
            # ITER
            self.iter = pow(2, 11) #2048
            log.debug("Iter set to %s" % self.iter)
            # K
            self.enckey = os.urandom(32)
            # L
            self.hshkey = os.urandom(32)
            # IV
            self.iv = os.urandom(16)
            # Tag
            self.tag = "PWS3"
            # EOF
            self.eof = "PWS3-EOFPWS3-EOF"
            self.headers = []
            self.hmacreq = []
            self.records = []

    def __len__(self):
        return len(self.records)

    def save(self):
        """ Save the safe to disk 
        """
        if self.mode == "RW":
            self.serialiaze()
            fil = open(self.filename, "w")
            fil.write(self.flfull)
            fil.close()
        else:
            raise ROSafe, "Safe is not in read/write mode"

    def serialiaze(self):
        """ Turn the in-memory objects into in-memory strings.         
        """
        # P'
        self._regen_pprime()
        # Regen b1b2
        self._regen_b1b2()
        # Regen b3b4
        self._regen_b3b4()
        # Regen H(P')
        self._regen_hpprime()
        # Regen hmac
        self.hmac = self.current_hmac()

        log.debug('Loading psafe')
        self.flfull = pack(
                                '4s32sI32s32s32s16s'
                                , self.tag
                                , self.salt
                                , self.iter
                                , self.hpprime
                                , self.b1b2
                                , self.b3b4
                                , self.iv
                            )
        log.debug("Pre-header flfull now %s", (self.flfull,))
        self.fulldata = ''
        for header in self.headers:
            self.fulldata += header.serialiaze()
            #log.debug("In header flfull now %s",(self.flfull,))
        for record in self.records:
            self.fulldata += record.serialiaze()
            #log.debug("In record flfull now %s",(self.flfull,))
        # Encrypted self.fulldata to self.cryptdata
        log.debug("Encrypting header/record data %s" % repr(self.fulldata))
        self.encrypt_data()
        self.flfull += self.cryptdata
        log.debug("Adding crypt data %s" % repr(self.cryptdata))
        self.flfull += pack('16s32s', self.eof, self.hmac)
        log.debug("Post EOF flfull now %s", (self.flfull,))

    def _regen_pprime(self):
        """Regenerate P'. This is the stretched version of salt and password. """
        self.pprime = stretchkey(self.password, self.salt, self.iter)
        log.debug("P' = % s" % repr(self.pprime))

    def _regen_b1b2(self):
        """Regenerate b1 and b2. This is the encrypted form of K. 
        
        """
        tw = MCRYPT('twofish', 'ecb')
        tw.init(self.pprime)
        self.b1b2 = tw.encrypt(self.enckey)
        log.debug("B1/B2 set to %s" % repr(self.b1b2))

    def _regen_b3b4(self):
        """Regenerate b3 and b4. This is the encrypted form of L. 
        """
        tw = MCRYPT('twofish', 'ecb')
        tw.init(self.pprime)
        self.b3b4 = tw.encrypt(self.hshkey)
        log.debug("B3/B4 set to %s" % repr(self.b3b4))

    def _regen_hpprime(self):
        """Regenerate H(P')
        Save the SHA256 of self.pprime. 
        """
        hsh = sha256_func()
        hsh.update(self.pprime)
        self.hpprime = hsh.digest()
        log.debug("Set H(P') to % s" % repr(self.hpprime))
        assert self.check_password()

    def load(self):
        """Load a psafe3 file
        Will raise PasswordError if the password is bad.
        Format:
        Name    Bytes    Type
        TAG     4     ASCII
        SALT    32    BIN
        ITER    4    INT 32
        H(P')    32    BIN
        B1    16    BIN
        B2    16    BIN
        B3    16    BIN
        B4    16    BIN
        IV    16    BIN
        Crypted    16n    BIN
        EOF    16    ASCII
        HMAC    32    BIN
        """
        log.debug('Loading psafe')
        log.debug('len: %d flful: %r' % (len(self.flfull[:152]), self.flfull[:152]))
        (self.tag, self.salt, self.iter, self.hpprime, self.b1b2, self.b3b4, self.iv) = unpack('4s32sI32s32s32s16s', self.flfull[:152])
        log.debug("Tag: %s" % repr(self.tag))
        log.debug("Salt: %s" % repr(self.salt))
        log.debug("Iter: %s" % repr(self.iter))
        log.debug("H(P'): % s" % repr(self.hpprime))
        log.debug("B1B2: % s" % repr(self.b1b2))
        log.debug("B3B4: % s" % repr(self.b3b4))
        log.debug("IV: % s" % repr(self.iv))
        self.cryptdata = self.flfull[152:-48]
        (self.eof, self.hmac) = unpack('16s32s', self.flfull[-48:])
        log.debug("EOF: % s" % repr(self.eof))
        log.debug("HMAC: % s" % repr(self.hmac))
        # Determine the password hash
        self.update_pprime()
        # Verify password
        if not self.check_password():
            raise PasswordError
        # Figure out the encryption and hash session keys
        log.debug("Calc'ing keys")
        self.calc_keys()
        log.debug("Going to decrypt data")
        self.decrypt_data()

        # Parse headers
        self.headers = []
        self.hmacreq = []
        self.remaining_headers = self.fulldata
        hdr = Create_Header(self._fetch_block)
        self.headers.append(hdr)
        self.hmacreq.append(hdr.hmac_data)
        #print str(hdr) +" - -"+ repr(hdr)
        while type(hdr) != EOFHeader:
            hdr = Create_Header(self._fetch_block)
            self.headers.append(hdr)
            #print str(hdr) +" - -"+ repr(hdr)

        # Parse DB
        self.records = []
        while len(self.remaining_headers) > 0:
            req = Record(self._fetch_block)
            self.records.append(req)

        if self.current_hmac(cached = True) != self.hmac:
            log.error('Invalid HMAC Calculated: %s File: %s' % (repr(self.current_hmac()), repr(self.hmac)))
            raise InvalidHMACError, "Calculated: % s File: % s" % (repr(self.current_hmac()), repr(self.hmac))

    def __str__(self):
        ret = ''
        for i in self.records:
            ret += str(i) + "\n\n"
        return ret

    def _fetch_block(self, num_blocks = 1):
        """Returns one or more 16 - byte block of data. Raises EOFError when there is no more data. """
        assert num_blocks > 0
        bytes = num_blocks * 16
        if bytes > len(self.remaining_headers):
            raise EOFError, "No more header data"
        ret = self.remaining_headers[:bytes]
        self.remaining_headers = self.remaining_headers[bytes:]
        return ret

    def calc_keys(self):
        """Calculate sessions keys for encryption and hmac. Is based on pprime, b1b2, b3b4"""
        tw = MCRYPT('twofish', 'ecb')
        tw.init(self.pprime)
        self.enckey = tw.decrypt(self.b1b2)
        # its ok to reuse; ecb doesn't keep state info
        self.hshkey = tw.decrypt(self.b3b4)
        log.debug("Encryption key K: %s " % repr(self.enckey))
        log.debug("HMAC Key L: %s " % repr(self.hshkey))
        
    def decrypt_data(self):
        """Decrypt encrypted portion of header and data"""
        log.debug("Creating mcrypt object")
        tw = MCRYPT('twofish', 'cbc')
        log.debug("Adding key & iv")
        tw.init(self.enckey, self.iv)
        log.debug("Decrypting data")
        self.fulldata = tw.decrypt(self.cryptdata)
                
    def encrypt_data(self):
        """Encrypted fulldata to cryptdata"""
        tw = MCRYPT('twofish', 'cbc')
        tw.init(self.enckey, self.iv)
        self.cryptdata = tw.encrypt(self.fulldata)

    def current_hmac(self, cached = False):
        """Returns the current hmac of self.fulldata"""
        data = ''
        for i in self.headers:
            log.debug("Adding hmac data %r from %r" % (i.hmac_data(), i.__class__.__name__))
            if cached:
                data += i.data
            else:
                data += i.hmac_data()
                #assert i.data == i.hmac_data(), "Working on %r where %r!=%r" % (i, i.data, i.hmac_data())
        for i in self.records:
            # TODO: Add caching support
            log.debug("Adding hmac data %r from %r" % (i.hmac_data(), i.__class__.__name__))
            data += i.hmac_data()
        log.debug("Building hmac with key %s", repr(self.hshkey))
        hm = HMAC(self.hshkey, data, sha256_mod)
        #print hm.hexdigest()
        log.debug("HMAC %s-%s", repr(hm.hexdigest()), repr(hm.digest()))
        return hm.digest()

    def check_password(self):
        """Check that the hash in self.pprime matches what's in the password safe. True if password matches hash in hpprime. False otherwise"""
        hsh = sha256_func()
        hsh.update(self.pprime)
        return hsh.digest() == self.hpprime

    def update_pprime(self):
        """Update self.pprime. This key is used to decrypt B1 / 2 and B3 / 4"""
        self.pprime = stretchkey(self.password, self.salt, self.iter)

    def close(self):
        """Close out open file"""
        self.fl.close()

    def __del__(self):
        try:
            self.fl.close()
        except:
            pass

    def listall(self):
        """
        Yield all entries in the form
                (uuid, title, group, username, password, notes)
        @rtype: [(uuid, title, group, username, password, notes),...]
        @return A list of tuples covering all known records. 
                """
        def nrwrapper(name):
            try:
                return record[name]
            except KeyError:
                return None

        for record in self.records:
            yield (
                nrwrapper('UUID')
                , nrwrapper('Title')
                , nrwrapper('Group')
                , nrwrapper('Username')
                , nrwrapper('Password')
                , nrwrapper('Notes')
            )

    def getEntries(self):
        """ Return a list of all records 
        @rtype: [Record,...]
        @return: A list of all records. 
        """
        return self.records
    
    def getpass(self, uuid = None):
        """Returns the password of the item with the given UUID
        @param uuid: UUID of the record to find
        @type uuid: UUID object
        @rtype: string
        @return: Password for the record with the given UUID. Raise an exception otherwise
        @raise UUIDNotFoundError  
        """
        for record in self.records:
            if record['UUID'] == uuid:
                return record['Password']
        raise UUIDNotFoundError, "UUID %s was not found. " % repr(uuid)

    def __getitem__(self, *args, **kwargs):
        return self.records.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        return self.records.__setitem__(*args, **kwargs)

    def getUUID(self):
        """Return the safe's uuid"""
        for hdr in self.headers:
            if type(hdr) == UUIDHeader:
                return hdr.uuid
        return uuid4()
    
    def setUUID(self, uuid = None):        
        for hdr in self.headers:
            if type(hdr) == UUIDHeader:
                hdr.uuid = str(uuid)
                return
        if uuid:
            self.headers.append(UUIDHeader(uuid = uuid))
        else:
            self.headers.append(UUIDHeader())

    def getVersion(self):
        """Return the safe's version"""
        for hdr in self.headers:
            if type(hdr) == VersionHeader:
                return hdr.version
    
    def setVersion(self, version = None):
        """Return the safe's version"""
        for hdr in self.headers:
            if type(hdr) == VersionHeader:
                hdr.version = version
                return
        if version:
            self.headers.append(VersionHeader(version = version))
        else:
            self.headers.append(VersionHeader())
        
    def getTimeStampOfLastSave(self):
        for hdr in self.headers:
            if type(hdr) == TimeStampOfLastSaveHeader:
                return hdr.lastsave
    
    def setTimeStampOfLastSave(self, timestamp):
        for hdr in self.headers:
            if type(hdr) == TimeStampOfLastSaveHeader:
                hdr.lastsave = timestamp.timetuple()
                return
        self.headers.append(TimeStampOfLastSaveHeader(lastsave = timestamp.timetuple()))
            
    def getLastSaveApp(self):
        for hdr in self.headers:
            if type(hdr) == LastSaveAppHeader:
                return hdr.lastSafeApp
    
    def setLastSaveApp(self, app):
        for hdr in self.headers:
            if type(hdr) == LastSaveAppHeader:
                hdr.lastSafeApp = app
                return
        self.headers.append(LastSaveAppHeader(lastSaveApp = app))
            
    def getLastSaveUser(self):
        for hdr in self.headers:
            if type(hdr) == LastSaveUserHeader:
                return hdr.username
    
    def setLastSaveUser(self, username):
        for hdr in self.headers:
            if type(hdr) == LastSaveUserHeader:
                hdr.username = username
                return
        self.headers.append(LastSaveUserHeader(username = username))
    
    def getLastSaveHost(self):
        for hdr in self.headers:
            if type(hdr) == LastSaveHostHeader:
                return hdr.hostname
    
    def setLastSaveHost(self, hostname):
        for hdr in self.headers:
            if type(hdr) == LastSaveHostHeader:
                hdr.hostname = hostname
                return
        self.headers.append(LastSaveHostHeader(hostname = hostname))
                
    def getDbName(self):
        """ Returns the name of the db according to the psafe headers """
        for hdr in self.headers:
            if type(hdr) == DBNameHeader:
                return hdr.dbName
    
    def setDbName(self, dbName):
        """ Returns the name of the db according to the psafe headers """
        for hdr in self.headers:
            if type(hdr) == DBNameHeader:
                hdr.dbName = dbName
                return
        self.headers.append(DBNameHeader(dbName = dbName))
            
    def getDbDesc(self):
        """ Returns the description of the db according to the psafe headers """
        for hdr in self.headers:
            if type(hdr) == DBDescHeader:
                return hdr.dbDesc
    
    def setDbDesc(self, dbDesc):
        """ Returns the description of the db according to the psafe headers """
        for hdr in self.headers:
            if type(hdr) == DBDescHeader:
                hdr.dbDesc = dbDesc
                return
        self.headers.append(DBDescHeader(dbDesc = dbDesc))

    def _get_lock_data(self):
        pid = os.getpid()
        host = socket.gethostname()
        fil = self.filename.replace('.psafe3', '.plk')
        from pickle import dumps
        return dumps((pid, host, fil))
        
    def lock(self):
        """ Acquire a lock on the DB. Raise an exception on failure """
        lfile = self.filename.replace('.psafe3', '.plk')
        # Make sure we don't already hold the lock
        if self.locked and os.access(lfile, os.R_OK):
            raise LockAlreadyAcquiredError
        
        if os.path.isfile(lfile):
            # May be a dead pid
            from pickle import loads
            f = open(lfile, 'rb')
            pid, host, fil = loads(f.read())
            f.close()
            if host == socket.gethostbyname():
                try:
                    os.kill(pid, 0) #@UndefinedVariable
                    raise AlreadyLockedError, "Other process is alive. Can't override lock. "
                except:
                    # Not really locked, remove stale lock
                    os.remove(lfile)
                    return self.lock()
            else:
                raise AlreadyLockedError, "Lock is on a different host. Can't try to unlock. "
        
        self.locked = lfile
                
        # Create the lock file with no race conditions
        # Should generate an OS error if the file already exists 
        try:
            fd = os.open(lfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, self._get_lock_data())
            os.close(fd)
        except OSError, e:
            raise AlreadyLockedError
        
    def unlock(self):
        """ Unlock the DB """
        if not self.locked:
            raise NotLockedError, "Not currently locked"
        try:
            os.remove(self.locked)
            self.locked = False
        except OSError:
            raise NotLockedError, "Obj reported as locked but no lock file exists"
                   
# Misc helper functions
def ispsafe3(filename):
    """Return True if the file appears to be a psafe v3 file. Does not do in-depth checks. """
    fil = open(filename, "r")
    data = fil.read(4)
    fil.close()
    return data == "PWS3"

if __name__ == "__main__":
    import doctest
    doctest.testmod()
