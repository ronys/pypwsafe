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
from psafefe.psafe.rpc._errors import *
from psafefe.psafe.rpc._auth import auth
from psafefe.psafe.models import *

@rpcmethod(name = 'psafe.read.getEntry', signature = ['string', 'string', 'int'])
@auth
def getEntry(username, password, entPK, **kw):
    """ Return a struct representing the requested entry """
    try:
        ent = MemPsafeEntry.objects.get(pk = entPK)
    except MemPsafeEntry.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.safe.safe.repo
    if repo.user_can_access(kw['user'], mode = "R"):
        return ent.todict()
    
    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError

@rpcmethod(name = 'psafe.read.getSafe', signature = ['string', 'string', 'int'])
@auth
def getSafe(username, password, entPK, **kw):
    """ Return a struct representing the requested psafe """
    try:
        ent = MemPSafe.objects.get(pk = entPK)
    except MemPSafe.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.repo
    if repo.user_can_access(kw['user'], mode = "R"):
        return ent.todict()
    
    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError

