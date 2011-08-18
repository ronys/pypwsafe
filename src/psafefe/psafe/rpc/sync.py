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
from psafefe.psafe.tasks import loadSafe
from psafefe.psafe.functions import getDatabasePasswordByUser

# Psafe entry methods
@rpcmethod(name = 'psafe.sync.updatePSafeCacheByPSafes', signature = ['boolean', 'string', 'string', 'array', 'boolean'])
@auth
def updatePSafeCacheByPSafes(username, password, entPKs, sync, **kw):
    """ Update the psafe cache for the given entities. If sync is true, 
    then wait for the cache to update before returning. """
    if kw['user'].has_perm('psafe.can_sync_passwordsafe'):
        # user has perms
        waits = []
        for entPK in entPKs:
            psafe = PasswordSafe.objects.get(pk = entPK)
            psafepass = getDatabasePasswordByUser(kw['user'], password, psafe)
            waits.append(loadSafe.delay(psafe_pk = entPK, password = psafepass)) #@UndefinedVariable
        # Doing sync, wait for all results
        if sync:
            for i in waits:
                i.wait()
    else:
        raise NoPermissionError

