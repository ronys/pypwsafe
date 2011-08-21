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
'''
Created on Aug 16, 2011

@author: gpmidi
'''
from rpc4django import rpcmethod
from psafefe.psafe.rpc.errors import *
from psafefe.psafe.rpc.auth import auth
from psafefe.psafe.models import *
from uuid import UUID

# Entry methods
@rpcmethod(name = 'psafe.read.getEntryByPK', signature = ['struct', 'string', 'string', 'int'])
@auth
def getEntryByPK(username, password, entPK, **kw):
    """ Return a struct representing the requested entry 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPK: The database id of the entry to return. 
    @type entPK: int
    @return: A dictionary containing the entities properties
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it.
    """
    try:
        ent = MemPsafeEntry.objects.get(pk = entPK)
    except MemPsafeEntry.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.safe.safe.repo
    if repo.user_can_access(kw['user'], mode = "R"):
        return ent.todict()
    
    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError

@rpcmethod(name = 'psafe.read.getEntryByUUID', signature = ['struct', 'string', 'string', 'int'])
@auth
def getEntryByUUID(username, password, entUUID, **kw):
    """ Return a struct representing the requested entry 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entUUID: UUID of the entry to pull as a dash separated string 
    @type entUUID: string    
    @return: A dictionary containing the entities properties
    @raise InvalidUUIDError: The UUID given isn't in a valid format or contains invalid chars. 
    @raise EntryDoesntExistError: The requested entry doesn't exist or the user doesn't have permission to read it. 
    """
    try:
        uuid = UUID(entUUID)
    except:
        raise InvalidUUIDError, "%r is not a valid UUID" % entUUID
    try:
        ent = MemPsafeEntry.objects.get(uuid = entUUID)
    except MemPsafeEntry.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.safe.safe.repo
    if repo.user_can_access(kw['user'], mode = "R"):
        return ent.todict()
    
    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError


#         Password Safe methods
@rpcmethod(name = 'psafe.read.getSafeByPK', signature = ['struct', 'string', 'string', 'int'])
@auth
def getSafeByPK(username, password, entPK, **kw):
    """ Return a struct representing the requested psafe 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param entPK: The database id of the safe to return. 
    @type entPK: int
    @return: A dict containing the properties of the requested safe. 
    """
    try:
        ent = MemPSafe.objects.get(pk = entPK)
    except MemPSafe.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.repo
    if repo.user_can_access(kw['user'], mode = "R"):
        return ent.todict()
    
    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError

@rpcmethod(name = 'psafe.read.getSafesForUser', signature = ['list', 'string', 'string'])
@auth
def getSafesForUser(username, password, getEntries = True, getEntryHistory = True, mode = 'R', **kw):
    """ Return a list of dicts representing all psafe files accessible by the requesting user. 
    @param username: Requesting user's login
    @type username: string
    @param password: Requesting user's login
    @type password: string
    @param getEntries: If True, include all of the safe's password entries as well. 
    @type getEntries: boolean
    @param getEntryHistory: If True, return all of the old passwords for each password entry. 
    @type getEntryHistory: boolean
    @param mode: Limit safes to ones where the user has the given permissions. "R" for read, "RW" for read/write, and "A" for admin. 
    @type mode: string
    @return: A list of dicts representing all of the password safes the requesting user has access to.  
    """
    # TODO: Make this faster...this way is dumb
    valid = {}
    for repo in PasswordSafeRepo.objects.all():
        if repo.user_can_access(kw['user'], mode = mode):
            for safe in repo.passwordsafe_set.all():
                # Dedep, just in case
                for memsafe in safe.mempsafe_set.all():
                    valid[memsafe.pk] = memsafe
    return [memsafe.todict(getEntries = getEntries, getEntryHistory = getEntryHistory) for memsafe in valid.values()]
    
