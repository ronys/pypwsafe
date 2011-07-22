#!/usr/bin/env python
#===============================================================================
# SYMANTEC:     Copyright © 2009-2011 Symantec Corporation. All rights reserved.
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
"""


"""
# Lets this lib work from both 2.4 and above
try:
        from hashlib import sha256_func #@UnresolvedImport
        from hashlib import sha256_mod #@UnresolvedImport
except:
        import Crypto.Hash.SHA256 as sha256_mod #@UnresolvedImport
        from Crypto.Hash.SHA256 import new as sha256_func #@UnresolvedImport
from mcrypt import MCRYPT #@UnresolvedImport
from hmac import new as HMAC
from PWSafeV3Headers import *
from PWSafeV3Records import *
from errors import *
import os, os.path
from struct import pack, unpack
import logging, logging.config

log = logging.getLogger("psafe.lib.init")
log.debug('initing')
from uuid import uuid4

def stretchkey(passwd, salt, count):
    """Streach a key. H(pass+salt)

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
    """
	filename	string		Full path to pwsafe
	password	string		Passsafe password
	fl		    File Object	PWSafe file handle
	flfull		string		Contents of pwsafe file
	pprime		string		Stretched key used in B1-B4
	enckey		string		K; session key for main data block
	hshkey		string		L; hmac key
	records		[Record]	List of all records we have
	hmacreq		[functions]	List of functions to run to generate hmac. Order matters when reading a 
	                        file.
	hmac		string		Originally its the hmac from the file. Should be updated when ever changes 
	                        are made.
	mode        string      RO,RW
	iv          string(16)  Initialization vector used for CBC mode when encrypting/decrypting the
	                        header and records. 
	# Passsafe fields
	version
	uuid
	prefs

	"""
    def __init__(self, filename, password, mode="RW"):
        log.debug('Creating psafe %s' % repr(filename))
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
            log.debug("Loading existing safe")
            self.filename = filename
            self.fl = open(self.filename, 'r')
            try:
                self.flfull = self.fl.read()
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
        if self.mode == "RW":
            self.serialiaze()
            fil = open(self.filename, "w")
            fil.write(self.flfull)
            fil.close()
        else:
            raise ROSafe, "Safe is not in read/write mode"

    def serialiaze(self):
        """
        
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
        log.debug("P'=%s" % repr(self.pprime))

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
        log.debug("Set H(P') to %s" % repr(self.hpprime))
        assert self.check_password()

    def load(self):
        """Load a psafe3 file
		Will raise PasswordError if the password is bad.
		Format:
		Name	Bytes	Type
		TAG 	4 	ASCII
		SALT	32	BIN
		ITER	4	INT 32
		H(P')	32	BIN
		B1	16	BIN
		B2	16	BIN
		B3	16	BIN
		B4	16	BIN
		IV	16	BIN
		Crypted	16n	BIN
		EOF	16	ASCII
		HMAC	32	BIN
		"""
        log.debug('Loading psafe')
        (self.tag, self.salt, self.iter, self.hpprime, self.b1b2, self.b3b4, self.iv) = unpack('4s32sI32s32s32s16s', self.flfull[:152])
        log.debug("Tag: %s" % repr(self.tag))
        log.debug("Salt: %s" % repr(self.salt))
        log.debug("Iter: %s" % repr(self.iter))
        log.debug("H(P'): %s" % repr(self.hpprime))
        log.debug("B1B2: %s" % repr(self.b1b2))
        log.debug("B3B4: %s" % repr(self.b3b4))
        log.debug("IV: %s" % repr(self.iv))
        self.cryptdata = self.flfull[152:-48]
        (self.eof, self.hmac) = unpack('16s32s', self.flfull[-48:])
        log.debug("EOF: %s" % repr(self.eof))
        log.debug("HMAC: %s" % repr(self.hmac))
        # Determin the password hash
        self.update_pprime()
        # Verify password
        if not self.check_password():
            raise PasswordError
        # Figure out the encryption and hash session keys
        self.calc_keys()
        self.decrypt_data()

        # Parse headers
        self.headers = []
        self.hmacreq = []
        self.remaining_headers = self.fulldata
        hdr = Create_Header(self._fetch_block)
        self.headers.append(hdr)
        self.hmacreq.append(hdr.hmac_data)
        #print str(hdr) +"--"+ repr(hdr)
        while type(hdr) != EOFHeader:
            hdr = Create_Header(self._fetch_block)
            self.headers.append(hdr)
            #print str(hdr) +"--"+ repr(hdr)

        # Parse DB
        self.records = []
        while len(self.remaining_headers) > 0:
            req = Record(self._fetch_block)
            self.records.append(req)

        if self.current_hmac(cached=True) != self.hmac:
            log.error('Invalid HMAC Calculated: %s File: %s' % (repr(self.current_hmac()), repr(self.hmac)))
            #raise InvalidHMACError, "Calculated: %s File: %s"%(repr(self.current_hmac()),repr(self.hmac))

    def __str__(self):
        ret = ''
        for i in self.records:
            ret += str(i) + "\n\n"
        return ret

    def _fetch_block(self, num_blocks=1):
        """Returns one or more 16-byte block of data. Raises EOFError when there is no more data. """
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
        tw = MCRYPT('twofish', 'cbc')
        tw.init(self.enckey, self.iv)
        self.fulldata = tw.decrypt(self.cryptdata)

    def encrypt_data(self):
        """Encrypted fulldata to cryptdata"""
        tw = MCRYPT('twofish', 'cbc')
        tw.init(self.enckey, self.iv)
        self.cryptdata = tw.encrypt(self.fulldata)

    def current_hmac(self, cached=False):
        """Returns the current hmac of self.fulldata"""
        data = ''
        for i in self.headers:
            log.debug("Adding hmac data %s", repr(i.hmac_data()))
            if cached:
                data += i.data
            else:
                data += i.hmac_data()
        for i in self.records:
            log.debug("Adding hmac data %s", repr(i.hmac_data()))
            data += i.hmac_data()
        log.debug("Building hmac with key %s", repr(self.hshkey))
        hm = HMAC(self.hshkey, data, sha256_mod)
        #print hm.hexdigest()
        log.debug("HMAC %s-%s", repr(hm.hexdigest()), repr(hm.digest()))
        return hm.digest()

    def check_password(self):
        """Check that the hash in self.pprime matches whats in the password safe. True if password matches hash in hpprime. False otherwise"""
        hsh = sha256_func()
        hsh.update(self.pprime)
        return hsh.digest() == self.hpprime

    def update_pprime(self):
        """Update self.pprime. This key is used to decrypt B1/2 and B3/4"""
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
        """Yield all entries in the form
                (uuid, title, group, username, password, notes)
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

    def getpass(self, uuid=None):
        """Returns the password of the item with the given UUID"""
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

    def getVersion(self):
        """Return the safe's version"""
        for hdr in self.headers:
            if type(hdr) == VersionHeader:
                return hdr.version

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

