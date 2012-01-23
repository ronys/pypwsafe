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
''' Tasks to update/delete/create password entries and password safes
Created on Aug 16, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
'''
#from celery.task import task #@UnresolvedImport
from celery.decorators import task #@UnresolvedImport
from psafefe.psafe.models import * #@UnusedWildImport
from psafefe.psafe.errors import * #@UnusedWildImport
from pypwsafe import PWSafe3, Record
from psafefe.psafe.tasks.load import loadSafe
import datetime
from socket import getfqdn

@task()
def newSafe(psafePK, psafePassword, userPK = None, dbName = None, dbDesc = None):
    """ Create a new, empty psafe and then
    load it into the cache. Will not error or overwrite
    duplicate safes. """
    if userPK:
        user = User.objects.get(pk = userPK)
    else:
        user = None
    psafe = PasswordSafe.objects.get(pk = psafePK)
    
    pypwsafe = PWSafe3(
                     filename = psafe.psafePath(),
                     password = psafePassword,
                     mode = "RW",
                     )
    # Set details
    pypwsafe.setVersion()
    pypwsafe.setTimeStampOfLastSave(datetime.datetime.now())
    pypwsafe.setUUID()
    pypwsafe.setLastSaveApp('PyPWSafe')
    if user:
        pypwsafe.setLastSaveUser(user.username)
    try:
        pypwsafe.setLastSaveHost(getfqdn())
    except:
        pass
    if dbName:
        pypwsafe.setDbName(dbName)
    if dbDesc:
        pypwsafe.setDbDesc(dbDesc)
    pypwsafe.save()
    assert loadSafe(psafe_pk = psafePK, password = psafePassword, force = True)
    
@task()
def addUpdateEntry(
             psafePK,
             psafePassword,
             username,
             password,
             group = None,
             title = None,
             uuid = None,
             note = None,
             created = None,
             pwModified = None,
             entryModified = None,
             lastAccess = None,
             expires = None,
             url = None,
             autoType = None,
             history = None,
             runCommand = None,
             email = None,
             ):
    """ Adds an entry to the given psafe. Update if it already exists. Reloads the psafe data once complete.
    @warning: Group, title, and username are used to determine if an entry should be updated.  
    """
    psafe = PasswordSafe.objects.get(pk = psafePK)
    pypwsafe = PWSafe3(
                     filename = psafe.psafePath(),
                     password = psafePassword,
                     mode = "RW",
                     )
    pypwsafe.lock()
    try:
        existing = None
        for record in pypwsafe.records:
            # If anything fails, it can't be a match
            try:
                if record.getUsername() == username and record.getTitle() == title and record.getGroup() == group:
                    existing = record
            except:
                pass
        
        if existing:
            newRecord = existing
        else:
            newRecord = Record()
        newRecord.setUsername(username)
        newRecord.setPassword(password)
        if group:
            newRecord.setGroup(group)
        if title:
            newRecord.setTitle(title)
        if uuid:
            newRecord.setUUID(uuid)
        else:
            newRecord.setUUID()
        if note:
            newRecord.setNote(note)
        if created:
            newRecord.setCreated(created)
        else:
            newRecord.setCreated(datetime.datetime.now())
        if pwModified:
            newRecord.setPasswordModified(pwModified)
        else:
            newRecord.setPasswordModified(datetime.datetime.now())
        if entryModified:
            newRecord.setEntryModified(entryModified)
        else:
            newRecord.setEntryModified(datetime.datetime.now())
        if lastAccess:
            newRecord.setLastAccess(lastAccess)
        else:
            newRecord.setLastAccess(datetime.datetime.now())
        if expires:
            newRecord.setExpires(expires)
        if url:
            newRecord.setURL(url)
        if autoType:
            newRecord.setAutoType(autoType)
        if history:
            newRecord.setHistory(history)
        if runCommand:
            newRecord.setRunCommand(runCommand)
        if email:
            newRecord.setEmail(email)
        pypwsafe.records.append(newRecord)
        pypwsafe.save()
    finally:
        pypwsafe.unlock()
    
    assert loadSafe(psafe_pk = psafePK, password = psafePassword, force = True)
    
    
