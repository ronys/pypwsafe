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
''' Psafe cache control
Created on Aug 16, 2011

@author: Paulson McIntyre <paul@gpmidi.net>
'''
from rpc4django import rpcmethod
from psafefe.psafe.rpc.errors import *
from psafefe.psafe.rpc.auth import auth
from psafefe.psafe.models import *
from psafefe.psafe.tasks import loadSafe
from psafefe.psafe.functions import getDatabasePasswordByUser

# Psafe sync methods
@rpcmethod(name = 'psafe.sync.updatePSafeCacheByPSafesByPK', signature = ['boolean', 'string', 'string', 'array', 'boolean'])
@auth
def updatePSafeCacheByPSafesByPK(username, password, entPKs, sync, **kw):
    """ Update the psafe cache for the given entities. If sync is true, 
    then wait for the cache to update before returning. 
    @note: Any safes that the user doesn't have a valid password for will be skipped.
    @warning: If sync is not set the count of successes will NOT include any errors that occur during sync. It will only include ones where the safe password lookup and object lookup succeeded.     
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPKs: A list of safe PKs that should have their cache updated.
    @type entPKs: list of ints
    @param sync: If True, wait for the safes to be updated before returning. 
    @type sync: boolean
    @return: The number of safes successfully updated
    @raise NoPermissionError: User doesn't have password safe sync permissions
    """    
    if kw['user'].has_perm('psafe.can_sync_passwordsafe'):
        # user has perms
        waits = []
        successes = 0
        for entPK in entPKs:
            try:
                psafe = PasswordSafe.objects.get(pk = entPK)
                psafepass = getDatabasePasswordByUser(kw['user'], password, psafe)
                waits.append(loadSafe.delay(psafe_pk = entPK, password = psafepass)) #@UndefinedVariable
                successes += 1
            except:
                pass
        # Doing sync, wait for all results
        if sync:
            for i in waits:
                try:
                    i.wait()
                except:
                    successes -= 1
        return successes
    else:
        raise NoPermissionError

@rpcmethod(name = 'psafe.sync.updatePSafeCacheByPSafesByUUID', signature = ['boolean', 'string', 'string', 'array', 'boolean'])
@auth
def updatePSafeCacheByPSafesByUUID(username, password, entUUIDs, sync, **kw):
    """ Update the psafe cache for the given entities. If sync is true, 
    then wait for the cache to update before returning. 
    @note: Any safes that the user doesn't have a valid password for will be skipped.
    @warning: If sync is not set the count of successes will NOT include any errors that occur during sync. It will only include ones where the safe password lookup and object lookup succeeded.     
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entUUIDs: A list of safe UUIDs that should have their cache updated.
    @type entUUIDs: list of strings
    @param sync: If True, wait for the safes to be updated before returning. 
    @type sync: boolean
    @return: The number of safes successfully updated
    @raise NoPermissionError: User doesn't have password safe sync permissions
    """    
    if kw['user'].has_perm('psafe.can_sync_passwordsafe'):
        # user has perms
        waits = []
        successes = 0
        for entUUID in entUUIDs:
            try:
                psafe = PasswordSafe.objects.get(uuid = entUUID)
                psafepass = getDatabasePasswordByUser(kw['user'], password, psafe)
                waits.append(loadSafe.delay(psafe_pk = entPK, password = psafepass)) #@UndefinedVariable
                successes += 1
            except:
                pass
        # Doing sync, wait for all results
        if sync:
            for i in waits:
                try:
                    i.wait()
                except:
                    successes -= 1
        return successes
    else:
        raise NoPermissionError
