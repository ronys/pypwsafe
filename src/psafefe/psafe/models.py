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
from django.db import models
from uuid import uuid4
from django.contrib.auth.models import User, Group
from psafefe.psafe.validators import *
from os.path import join

class PasswordSafeRepo(models.Model):
    """ A place where psafes can be stored """
    class Meta:
        ordering = [
                    'name',
                    ]
        abstract = True
        verbose_name = "Password Safe Repo"
        verbose_name_plural = "Password Safe Repos"
        permissions = (
                       ('can_sync', 'Can sync all safes in this repo'),
                       )
        
        
    name = models.CharField(
                            null = False,
                            blank = False,
                            length = 255,
                            verbose_name = "Name",
                            help_text = "A human readable name for the password safe repository",
                            )
    path = models.CharField(
                            null = False,
                            blank = False,
                            length = 1024 * 1024,
                            verbose_name = "Server Location",
                            help_text = "The location on the server of the password safes",
                            validators = [
                                        validate_r_ok,
                                        ],
                            )
    adminGroups = models.ManyToManyField(
                                           Group,
                                           verbose_name = "Admin Groups",
                                           help_text = "Groups that have administrative access to this repo",
                                           )
    readAllowGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Read-Allow Groups",
                                               help_text = "Groups that have read access to this repo",
                                               )
    writeAllowGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Write-Allow Groups",
                                               help_text = "Groups that have write access to this repo",
                                               )
    # These are applied before the allows
    readDenyGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Read-Deny Groups",
                                               help_text = "Groups that do not have read access to this repo. This overrides the read-allow groups list. ",
                                               )
    writeDenyGroups = models.ManyToManyField(
                                               Group,
                                               verbose_name = "Write-Deny Groups",
                                               help_text = "Groups that do not have write access to this repo. This overrides the write-allow groups list. ",
                                               )
    # Helpers
    def _in_group(self, user, group_relate):
        """ Returns true if the user is in a group that is part of the many-to-many
        related group listed above """
        groups = user.groups.all()
        for group in groups:
            if group in group_relate.all():
                return True
        return False
        
    def user_can_access(self, user, mode = "R"):
        """ Returns true if the user has access to this repo. Mode should
        be "R" for read only, "RW" for read/write, or "A" for admin. """
        if mode == "R":
            return self._in_group(user, self.readAllowGroups) and not self._in_group(user, self.readDenyGroups)
        elif mode == "A":
            return self._in_group(user, self.adminGroups)
        elif mode == "RW":
            return self._in_group(user, self.readAllowGroups) and not self._in_group(user, self.readDenyGroups) and self._in_group(user, self.writeAllowGroups) and not self._in_group(user, self.writeDenyGroups)
        else:
            raise ValueError, "Mode %r is not a valid mode" % mode
    
    # Random ideas: 
    # Include options for storing all safes in a GIT repo
    # Add per-user permissions too
    # Add user-created groups or something to that effect
    
class PasswordSafe(models.Model):
    """ Keep a record of all psafes that we should track
    Do NOT store any confidential info from the safe. 
    """
    class Meta:
        ordering = [
                    'repo',
                    'filename',
                    'uuid',
                    ]
        verbose_name = "Password Safe"
        verbose_name_plural = "Password Safes"
        unique_together = (
                           # Can't do this because filename is too long
                           # TODO: Add a filename_md5 or something 
                           # ('filename','repo'),
                           )
        permissions = (
                       ('can_sync', 'Can sync individual safes'),
                       )
        
    uuid = models.CharField(
                            # can't use as PK as two psafes may have the same uuid
                            # primary_key = True,
                            null = False,
                            # Make it a callable otherwise all will default to the same (at least within one instance)
                            default = lambda: str(uuid4()),
                            length = 36,
                            verbose_name = "UUID",
                            help_text = "Password Safe GUID",
                            editable = False,
                            )
    filename = models.CharField(
                                # The system should note this safe as "missing" if it can't be found atm. 
                                null = True,
                                length = 1024 * 1024,
                                verbose_name = "Password Safe Path",
                                help_text = "The full path to the password safe from the worker's perspective",
                                )
    repo = models.ForeignKey(
                             PasswordSafeRepo,
                             verbose_name = "Repository",
                             help_text = "The password safe repository that this safe resides in",
                             )
    
    owner = models.ForeignKey(
                              User,
                              # If null it's a normal psafe, if set, it's a personal psafe
                              null = True,
                              verbose_name = "Owner",
                              help_text = "The owning user of the password safe",
                              ) 
    
    def psafePath(self):
        """ Returns the full path on the server to the psafe file """
        return join(self.repo.path, self.filename)
    
# Memory resident tables
class MemPSafe(models.Model):
    """ Represent a cache'd psafe """
    safe = models.ForeignKey(
                             PasswordSafe,
                             null = False,
                             verbose_name = "Password Safe File",
                             help_text = "Refrence to the psafe file",
                             editable = False,
                             )
    uuid = models.CharField(
                            # can't use as PK as two psafes may have the same uuid
                            # primary_key = True,
                            null = False,
                            # Make it a callable otherwise all will default to the same (at least within one instance)
                            default = lambda: str(uuid4()),
                            length = 36,
                            verbose_name = "UUID",
                            help_text = "Password Safe GUID",
                            editable = False,
                            )
    dbName = models.CharField(
                              null = True,
                              default = None,
                              blank = True,
                              length = 1024 * 1024,
                              verbose_name = "Database Name",
                              )
    dbDescription = models.TextField(
                                     null = True,
                                     blank = True,
                                     default = None,
                                     length = 1024 * 1024 * 1024,
                                     verbose_name = "Database Description",
                                     )
    dbPassword = models.CharField(
                                  null = False,
                                  blank = True,
                                  default = "bogus12345",
                                  length = 1024 * 1024,
                                  verbose_name = "Database Password",
                                  )
    dbTimeStampOfLastSafe = models.DateTimeField(
                                                 null = True,
                                                 verbose_name = "Last Save",
                                                 help_text = "Date/Time of last Password Safe save",
                                                 )
    dbLastSaveApp = models.CharField(
                                     null = True,
                                     verbose_name = "Last Save App",
                                     )
    dbLastSaveHost = models.CharField(
                                     null = True,
                                     verbose_name = "Last Save Host",
                                     )
    dbLastSaveUser = models.CharField(
                                     null = True,
                                     verbose_name = "Last Save User",
                                     )
    # Cache params
    fileLastModified = models.DateTimeField(
                                            null = False,
                                            verbose_name = "File Last Modified",
                                            editable = False,
                                            )
    fileLastSize = models.IntegerField(
                                      null = False,
                                      verbose_name = "File Last Size",
                                      editable = False,
                                      )
    # TODO: Add in safe HMAC validation checks too

    def todict(self, getEntries = True, getEntryHistory = True):
        """ Return an XML-RPC safe dictionary of the data. Null 
        fields are deleted! """
        ret = {
             'UUID':self.uuid,
             'Name':self.dbName,
             'Description':self.dbDescription,
             'Password':self.dbPassword,
             'Last Save Time':self.dbTimeStampOfLastSafe,
             'Last Save App':self.dbLastSaveApp,
             'Last Save Host':self.dbLastSaveHost,
             'Last Save User':self.dbLastSaveUser,
             }
        if getEntries:
            ret['Entries'] = [i.todict(history = getEntryHistory) for i in self.mempsafeentry_set.all()]
        for k, v in ret.items():
            if v is None:
                del ret[k]
        return ret 
    
    
class MemPsafeEntry(models.Model):
    """ Represent a cached password safe entry """
    class Meta:        
        unique_together = (
                           ('safe', 'uuid'),
                           )
    safe = models.ForeignKey(
                             MemPSafe,
                             null = False,
                             verbose_name = "Password Safe",
                             )
    uuid = models.CharField(
                            # can't use as PK as two psafes may have the same uuid
                            # primary_key = True,
                            null = False,
                            # Make it a callable otherwise all will default to the same (at least within one instance)
                            default = lambda: str(uuid4()),
                            length = 36,
                            verbose_name = "UUID",
                            help_text = "Entry GUID",
                            editable = False,
                            )
    group = models.CharField(
                             null = True,
                             default = None,
                             length = 4096,
                             verbose_name = "Group",
                             help_text = "Dot separated group listing for the entry",
                             )
    title = models.CharField(
                             null = True,
                             default = None,
                             length = 4096,
                             verbose_name = "Title",
                             )
    username = models.CharField(
                             null = True,
                             default = None,
                             length = 4096,
                             verbose_name = "Username",
                             )
    notes = models.TextField(
                             null = True,
                             default = None,
                             length = 1024 * 1024,
                             verbose_name = "Notes",
                             )
    password = models.CharField(
                             null = True,
                             default = None,
                             length = 4096,
                             verbose_name = "Password",
                             )
    creationTime = models.DateTimeField(
                                        null = True,
                                        default = None,
                                        verbose_name = "Creation Time",
                                        )
    passwordModTime = models.DateTimeField(
                                           null = True,
                                           default = None,
                                           verbose_name = "Password Last Modification Time",
                                           )
    accessTime = models.DateTimeField(
                                      null = True,
                                      default = None,
                                      verbose_name = "Last Access Time",
                                      )
    passwordExpiryTime = models.DateTimeField(
                                              null = True,
                                              verbose_name = "Password Expiry Time",
                                              )
    modTime = models.DateTimeField(
                                   null = True,
                                   verbose_name = "Last Modification Time",
                                   )
    # Don't use a URL field - We don't want to risk any validation
    # Plus psafe doesn't guarantee it's a URL
    url = models.CharField(
                           null = True,
                           default = None,
                           length = 4096,
                           verbose_name = "URL",
                           )
    autotype = models.CharField(
                           null = True,
                           default = None,
                           length = 4096,
                           verbose_name = "Autotype String",
                           )
    runCommand = models.CharField(
                           null = True,
                           default = None,
                           length = 4096,
                           verbose_name = "Run Command",
                           )
    # Don't use an email field as psafe doesn't make any guarantees about the value
    email = models.CharField(
                           null = True,
                           default = None,
                           length = 4096,
                           verbose_name = "Email",
                           )
    
    def todict(self, history = True):
        """ Return an XML-RPC safe dictionary of the data. Null 
        fields are deleted! """
        ret = {
             'UUID':self.uuid,
             'Group':self.group,
             'Title':self.title,
             'Username':self.username,
             'Notes':self.notes,
             'Password':self.password,
             'Creation Time':self.creationTime,
             'Password Last Modification Time':self.passwordModTime,
             'Last Access Time':self.accessTime,
             'Password Expiry':self.passwordExpiryTime,
             'Entry Last Modification Time':self.modTime,
             'URL':self.url,
             'AutoType':self.autotype,
             'Run Command':self.runCommand,
             'Email':self.email,
             }
        if history:
            ret['History'] = [dict(Password = i.password, CreationTime = i.creationTime) for i in self.mempasswordentryhistory_set.all()]
        for k, v in ret.items():
            if v is None:
                del ret[k]
        return ret 
    
class MemPasswordEntryHistory(models.Model):
    """ Old passwords for the given entry """
    entry = models.ForeignKey(
                              MemPsafeEntry,
                              null = False,
                              verbose_name = "Entry",
                              )
    password = models.CharField(
                             null = True,
                             default = None,
                             length = 4096,
                             verbose_name = "Old Password",
                             )
    creationTime = models.DateTimeField(
                                        null = True,
                                        default = None,
                                        verbose_name = "Creation Time",
                                        )
