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

@author: gpmidi
'''
from rpc4django import rpcmethod
from psafefe.psafe.rpc._errors import *
from psafefe.psafe.rpc._auth import auth
from psafefe.psafe.models import *
from psafefe.psafe.tasks import newPersonalSafe
from psafefe.psafe.functions import getDatabasePasswordByUser

# Psafe entry methods
@rpcmethod(name = 'psafe.personal.setPsafePassword', signature = ['boolean', 'string', 'string', 'int', 'string'])
@auth
def setPsafePassword(username, password, safePK, safePassword, **kw):
    """ Update the psafe cache for the given entities. If sync is true, 
    then wait for the cache to update before returning. """
    try:
        ent = MemPsafeEntry.objects.get(pk = safePK)
    except MemPsafeEntry.DoesNotExist:
        raise EntryDoesntExistError
    
    repo = ent.safe.safe.repo
    if repo.user_can_access(kw['user'], mode = "R"):
        # User should have access to the requested safe
        
    # User doesn't have access so it might as well not exist
    raise EntryDoesntExistError

