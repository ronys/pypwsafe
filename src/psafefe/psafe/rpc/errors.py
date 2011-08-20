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
''' XML-RPC Errors
Created on Aug 17, 2011

@author: gpmidi
'''


class NotAuthorizedError(ValueError):
    """ User failed to authenticate """

class NoPermissionError(NotAuthorizedError):
    """ The user doesn't have the required permissons """

class BadUsernamePasswordError(NotAuthorizedError):
    """ User provided an incorrect username/password combo """
    
class InactiveUserError(NotAuthorizedError):
    """ User isn't active """
    
class EntryDoesntExistError(NoPermissionError):
    """ The requested entry doesn't exist or the user doens't have 
    permission to access it. """
    
