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
''' Tasks to load/reload password safes into the cache
Created on Aug 16, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
'''
#from celery.task import task #@UnresolvedImport
from celery.decorators import task #@UnresolvedImport
from psafefe.psafe.models import *
from psafefe.psafe.errors import *
from pypwsafe import PWSafe3
import stat

@task()
def loadSafe(psafe_pk, password, force = False):
    """ Cache  password safe. Returns True if the cache was updated. False otherwise. """
    try:
        psafe = PasswordSafe.objects.get(pk = psafe_pk)
    except PasswordSafe.DoesNotExist:
        raise PasswordSafeDoesntExist, "Password safe object %r doesn't exist" % psafe_pk
    if not os.access(psafe.psafePath(), os.R_OK):
        raise NoAccessToPasswordSafe, "Can't read psafe file %r" % psafe.psafePath()
    try:
        memPSafe = MemPSafe.objects.get(safe = psafe)
    except MemPSafe.DoesNotExist:
        memPSafe = MemPSafe(
                            safe = psafe,
                            )
    # Check if we need to
    if not force and os.stat(psafe.psafePath())[stat.ST_MTIME] == memPSafe.fileLastModified and memPSafe.fileLastSize == os.stat(psafe.psafePath())[stat.ST_SIZE]:
        return False
    
    # Save first, just in case
    memPSafe.fileLastModified = os.stat(psafe.psafePath())[stat.ST_MTIME]
    memPSafe.fileLastSize = os.stat(psafe.psafePath())[stat.ST_SIZE]
    
    # Let standard psafe errors travel on up    
    pypwsafe = PWSafe3(
                     filename = psafe.psafePath(),
                     password = password,
                     mode = "R",
                     )
    # Update/set attributes
    memPSafe.uuid = pypwsafe.getUUID()
    memPSafe.dbName = psafe.getDbName()
    memPSafe.dbDescription = psafe.getDbDesc()
    memPSafe.dbPassword = password
    memPSafe.dbTimeStampOfLastSafe = psafe.getTimeStampOfLastSave()
    memPSafe.dbLastSaveApp = psafe.getLastSaveApp()
    memPSafe.dbLastSaveHost = psafe.getLastSaveHost()
    memPSafe.dbLastSaveUser = psafe.getLastSaveUser()
    
    memPSafe.save()
    
    # All entries in db. Remove from list after updating.  
    remaining = {}
    for i in MemPsafeEntry.objects.filter(safe = pypwsafe):
        if i.uuid in remaining: 
            raise DuplicateUUIDError, "Entry %r has the same UUID as %r" % (i, remaining[i.uuid])
        else:
            remaining[i.uuid] = i
        
    updated = {}
    
    for entry in pypwsafe.getEntries():
        # Find the entry to create it (by uuid)
        if entry.getUUID() in remaining:
            memEntry = remaining[entry.getUUID()]
            del remaining[entry.getUUID()]
            updated[entry.getUUID()] = memEntry
        else:
            memEntry = MemPsafeEntry(
                                   safe = memPSafe,
                                   )
        # Update the entry
        memEntry.group = '.'.join(entry.getGroup())
        memEntry.title = entry.getTitle()
        memEntry.username = entry.getUsername()
        memEntry.notes = entry.getNote()
        memEntry.password = entry.getPassword()
        memEntry.creationTime = entry.getCreated()
        memEntry.passwordModTime = entry.getPasswordModified()
        memEntry.accessTime = entry.getLastAccess()
        memEntry.passwordExpiryTime = entry.getExpires()
        memEntry.modTime = entry.getEntryModified()
        memEntry.url = entry.getURL()
        memEntry.autotype = entry.getAutoType()
        memEntry.runCommand = entry.getRunCommand()
        memEntry.email = entry.getEmail()
        
        memEntry.save()
        
        org = {}
        for i in MemPasswordEntryHistory.objects.filter(entry = memEntry):
            org[repr(i.creationTime) + i.password] = i
        found = [] 
        for old in memEntry.getHistory():
            t = repr(repr(old['saved']) + old['password'])
            if t in org:
                memOld = org[t]
                del org[t]
                found.append(memOld)
            else:
                memOld = MemPasswordEntryHistory(entry = memEntry, password = old['password'], creationTime = old['saved'])
                memOld.save()
        # Remove all other old password entries
        for removedEntry in org.values():
            removedEntry.delete()
    # Remove all other entries
    for removedEntry in remaining.values():
        removedEntry.delete()
    
    return True
        
