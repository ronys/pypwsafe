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
''' Helper functions
Created on Aug 17, 2011

@author: gpmidi
'''
from django.contrib.auth.models import User, Group
from psafefe.psafe.models import *
from os.path import join
from django.conf import settings
import os
from psafefe.psafe.errors import *
from psafefe.psafe.rpc.errors import *

def getPersonalPsafeRepo():
    """ Returns the repo for the personal psafes """
    try:
        p = PasswordSafeRepo.objects.get(pk = 1)
        if p.path != settings.PSAFE_PERSONAL_PATH:
            p.path = settings.PSAFE_PERSONAL_PATH
            p.save()
    except PasswordSafeRepo.DoesNotExist:
        p = PasswordSafeRepo(pk = 1, name = "Personal Password Safes", path = settings.PSAFE_PERSONAL_PATH)
        p.save()
    return p

def getUsersPersonalSafe(user, userPassword, wait = True):
    personalRepo = getPersonalPsafeRepo()
    name = "User_Password_Safe_%s.psafe3" % user.username
    try:
        psafe = PasswordSafe.objects.get(repo = personalRepo, filename = name, owner = user)
    except PasswordSafe.DoesNotExist:
        psafe = PasswordSafe(repo = personalRepo, filename = name, owner = user)
        psafe.save()
    if not os.access(psafe.psafePath(), os.R_OK):
        # Create the safe
        from psafefe.psafe.tasks import newSafe
        task = newSafe.delay(#@UndefinedVariable
                          userPK = user.pk,
                          psafePK = psafe.pk,
                          psafePassword = userPassword,
                          dbName = "Personal Password Safe For %r" % user.username,
                          )
        if wait: 
            task.wait() 
    return psafe
    
def getDatabasePasswordByUser(user, userPassword, psafe, ppsafe = None):
    """ Returns the password to decrypt psafe from the user's
    personal DB. Raise an error if the user doesn't have the
    password """
    if not ppsafe:
        ppsafe = getUsersPersonalSafe(user, userPassword)
    # work delayed 
    ents = MemPsafeEntry.objects.filter(safe = MemPSafe.objects.get(safe = ppsafe))
    ents = ents.filter(group = "Password Safe Passwords.%d" % psafe.repo.pk)
    ents = ents.filter(title = "PSafe id %d" % psafe.pk)
    ents = ents.filter(username = psafe.filename)    
    
    # Use len so we cache results instead of count
    if len(ents) == 1:
        return ents[0].password
    elif len(ents) == 0:
        raise NoPasswordForPasswordSafe, "User %r doesn't have the password for safe %d" % (user, psafe.pk)
    else:
        raise ValueError, "Unexpected number of entries matched search for a psafe entries. Got %d results. " % len(ents)

def setDatabasePasswordByUser(user, userPassword, psafe, psafePassword, wait = True):
    """ Set/Create the password for the given psafe """
    # Pull the safe they want to set the pw for so we can
    # make sure they should have access to it
    try:
        ent = MemPsafeEntry.objects.get(pk = psafe.pk)
    except MemPsafeEntry.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.safe.safe.repo
    if not repo.user_can_access(user, mode = "R"):
        # User doesn't have access so it might as well not exist
        raise EntryDoesntExistError
    
    # User should have access to the requested safe
    ppsafe = getUsersPersonalSafe(user, userPassword)

    from psafefe.psafe.tasks import addUpdateEntry
    task = addUpdateEntry.delay(#@UndefinedVariable
                                psafePK = ppsafe.pk,
                                psafePassword = userPassword,
                                username = psafe.filename,
                                password = psafePassword,
                                group = "Password Safe Passwords.%d" % psafe.repo.pk,
                                title = "PSafe id %d" % psafe.pk,
                                note = '',
                                )
    if wait:
        task.wait()
    
    
        
        
    
    
    
