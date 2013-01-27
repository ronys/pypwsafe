#!/usr/bin/env python
#===============================================================================
# This file is part of PyPWSafe.
#
# PyPWSafe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# PyPWSafe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PyPWSafe. If not, see http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
#===============================================================================

import datetime
from getpass import getpass
import logging, logging.config
from optparse import make_option, OptionParser, OptionGroup
from socket import getfqdn
import string
import sys
import time
from uuid import UUID

# simplify the naming
Record = None
PWSafe3 = None

class PWSafeCLIError(Exception):
    pass

class PWSafeCLIValidationError(Exception):
    pass

VALID_ATTRIBUTES = ["group", "title", "username", "password", "UUID", "note", "created", "PasswordModified",
                    "EntryModified", "LastAccess", "expires", "email", "URL", "AutoType"]

def get_record_attr(record, attr):
    if not attr[0].isupper():
        attr = attr.title()
    bound_method = getattr(record, "get%s" % attr)
    return bound_method()

def match_valid(record, **params):
    if not params:
        return False

    valid = False

    for key, value in params.items():
         if value is None:
             continue
         valid = get_record_attr(record, key) == value
         if not valid:
             return False

    return valid

def get_matching_records(psafe, **params): # pragma: no cover
    return [ r for r in psafe.records if match_valid(r, **params) ]

def new_safe(filename, password, username = None,
             dbname = None, dbdesc = None): # pragma: no cover
    safe = PWSafe3(filename = filename, password = password, mode = "RW") 

    # Set details
    safe.setVersion()
    safe.setTimeStampOfLastSave(datetime.datetime.now())
    safe.setUUID()
    safe.setLastSaveApp('psafecli')

    if username:
        safe.setLastSaveUser(username)

    try:
        safe.setLastSaveHost(getfqdn())
    except:
        pass

    if dbname:
        safe.setDbName(dbname)
    if dbdesc:
        safe.setDbDesc(dbdesc)

    safe.save()

    return safe

def add_or_update_record(psafe, record, options): # pragma: no cover
    """ Adds an entry to the given psafe. Update if it already exists. Reloads the psafe data once complete.
"""
    now = datetime.datetime.now()

    if record is None:
        record = Record()
        record.setCreated(now)
    else:
        record.setEntryModified(now)

    if options.username:
        record.setUsername(options.username)

    if options.password:
        record.setPassword(options.password)

    record.setLastAccess(now)
    record.setPasswordModified(now)

    if options.group:
        record.setGroup(options.group)

    if options.title:
        record.setTitle(options.title)

    if options.UUID:
        record.setUUID(options.UUID)

    if options.expires:
        record.setExpires(options.expires)

    if options.url:
        record.setURL(options.url)

    if options.email:
        record.setEmail(options.email)

    psafe.records.append(record)
    psafe.save()
    return record.getUUID()

def collect_record_options(options):
    collected = {}
    potentials = ["group", "title", "username", "UUID"]
    for item in potentials:
        value = getattr(options, item)
        if value is not None:
            collected[item] = value
    return collected

def show_records(records, attributes): # pragma: no cover
    if not attributes:
        # show all attributes
        attributes = VALID_ATTRIBUTES

    for record in records:
        print "["
        for i in attributes:
            attr = i
            if not i[0].isupper():
                attr = attr.title()
            print "    %s: %s" % (attr, get_record_attr(record, i))
        print "]"

def get_safe(filename, password): # pragma: no cover
    safe = None

    try:
        safe = PWSafe3(filename = filename,
                       password = password,
                       mode = "RW")
    except pypwsafe.errors.PasswordError:
        raise PWSafeCLIError("Invalid password for safe")

    return safe

class Locked(object): # pragma: no cover
    def __init__(self, lock):
        self.lock = lock

    def __enter__(self):
        self.lock.lock()

    def __exit__(self, type, value, tb):
        self.lock.unlock()

def add_validator(options):
    if options.title is None:
        raise PWSafeCLIValidationError("--title must be specified")
    if options.password is None:
        raise PWSafeCLIValidationError("--password must be specified")

def add_action(options): # pragma: no cover
    safe = get_safe(options.filename, options.safe_password)
    with Locked(safe):
        result = add_or_update_record(safe, None, options)
    if options.verbose:
        print result

def delete_validator(options):
    if options.UUID is None:
        raise PWSafeCLIValidationError("--uuid must be specified")

def delete_action(options): # pragma: no cover
    safe = get_safe(options.filename, options.safe_password)

    with Locked(safe):
        records = get_matching_records(safe, {"UUID": options.UUID})
        count = len(records)
        if count == 0:
            raise PWSafeCLIError("no matching records found")
        elif count > 1:
            raise NotImplementedError("implement multiple record choice")

        safe.records.remove(records[0])
        safe.save()    

def display_validator(option):
    attrs = option.split(',')
    try:
        pos = attrs.index("uuid")
        attrs[pos] = "UUID"
    except ValueError:
        pass

    unsupported = [ field for field in attrs if not is_valid_field_name(field) ]
    if unsupported:
        raise PWSafeCLIValidationError("unsupport display fields: %s" % unsupported)

def is_valid_field_name(field):
    if field in VALID_ATTRIBUTES:
        return True
    return False

def dump_validator(options): # pragma: no cover
    if options.display:
        display_validator(options.display)

def dump_action(options): # pragma: no cover
    safe = get_safe(options.filename, options.safe_password)

    with Locked(safe):
        if not safe.records:
            raise PWSafeCLIError("No records")

        show_records(safe.records, options.display)

def get_validator(options):
    if not any([ getattr(options, attr) for attr in ("group", "title", "username", "UUID")]):
        raise PWSafeCLIValidationError("one of --group, --title, --username or --uuid must be provided")

    if options.display:
        display_validator(options.display)

def get_action(options): # pragma: no cover
    record_options = collect_record_options(options)

    safe = get_safe(options.filename, options.safe_password)

    with Locked(safe):
        records = get_matching_records(safe, **record_options)
        if not records:
            raise PWSafeCLIError("No records matching %s found" % record_options)

        show_records(records, options.display)

def init_validator(options):
    pass

def init_action(options): # pragma: no cover
    safe = new_safe(options.filename, options.safe_password, options.username,
                    options.dbname, options.dbdesc)

def update_validator(options):
    if not options.UUID:
        raise PWSafeCLIValidationError("must provide --uuid")

def update_action(options): # pragma: no cover
    record_options = collect_record_options(options)

    safe = get_safe(options.filename, options.safe_password)

    with Locked(safe):
        records = get_matching_records(safe, **record_options)
        count = len(records)
        if count == 0:
            raise PWSafeCLIError("No records matching %s found" % record_options)
        elif count > 1:
            raise NotImplementedError("implement multiple record choice")
        add_or_update_records(safe, records[0], options)

usage_message = """
Usage: psafecli [add|delete|get|init|update]

Run help for a subcommand for more options.
"""

def makeArgParser():
    parsers = {}

    base_options = [
        make_option("-f", "--file", dest="filename",
                    help="use FILE as PWSafe container", metavar="FILE"),
        make_option("--verbose", action="store_true"),
        make_option("--debug", action="store_true"),
    ]

    common_record_options = [
        make_option("--email", help="E-mail for contact person of Record"),
        make_option("--group", help="group of Record"),
        make_option("--title", help="title of Record"),
        make_option("--username", help="user of Record"),
        make_option("--uuid", dest="UUID", help="UUID of Record"),
    ]

    record_options = [
        make_option("--expires", help="Date Record expires ex. 2014-07-03 15:30"),
        make_option("--password", help="password of Record (not the Safe itself)"),
        make_option("--url", help="URL for Record"),
    ]

    display_option = make_option("--display", help="comma separated list of record attributes to display from this list: %s" % VALID_ATTRIBUTES)

    parser = OptionParser(option_list=base_options,
                          usage="psafecli init [options]")
    parser.add_option("--dbname", help="Name of new DB")
    parser.add_option("--dbdesc", help="Description of new DB")
    parser.add_option("--username", help="user of Safe")
    parsers["init"] = parser

    parser = OptionParser(option_list=(base_options + [display_option]),
                          usage="psafecli dump [options]")
    parsers["dump"] = parser

    parser = OptionParser(option_list=(base_options + common_record_options + [display_option]),
                          usage="psafecli get [options]")
    parsers["get"] = parser

    parser = OptionParser(option_list=(base_options + common_record_options + record_options), usage="psafecli add [options]")
    parsers["add"] = parser

    parser = OptionParser(option_list = base_options,
                          usage="psafecli delete [options]")
    parser.add_option("--uuid", dest="UUID", help="UUID of Record")
    parsers["delete"] = parser

    parser = OptionParser(option_list=(base_options + common_record_options + record_options), usage="psafecli update [options]")
    parsers["update"] = parser

    return parsers

def parse_commandline(parsers, argv):
    if len(argv) == 1:
        raise PWSafeCLIValidationError("must specify a command to run")
    elif argv[1].startswith('-'):
        raise PWSafeCLIValidationError(usage_message)

    action = argv[1]

    if action not in parsers.keys():
        raise PWSafeCLIValidationError("unknown action: %s" % action)

    parser = parsers[action]

    (options, args) = parser.parse_args(argv[2:])

    options.action = action

    if options.debug:
        logger = logging.getLogger('psafe')
        logger.setLevel(logging.DEBUG)

    if options.filename is None:
        parser.error("Must provide filename")

    if parser.has_option("--group") and options.group:
        options.group = options.group.split('.')

    if parser.has_option("--uuid") and options.UUID:
        options.UUID = UUID(options.UUID)

    if parser.has_option("--expires") and options.expires:
        try:
            options.expires = time.strptime(options.expires, "%Y-%m-%d %H:%M")
        except ValueError:
            raise PWSafeCLIValidationError("date entered does not match %Y-%m-%d %H:%M format")

    options.safe_password = None

    return options

def main(options): # pragma: no cover
    actions = { "add": (add_validator, add_action),
                "delete": (delete_validator, delete_action),
                "dump": (dump_validator, dump_action),
                "get": (get_validator, get_action),
                "init": (init_validator, init_action),
                "update": (update_validator, update_action),
    }

    validator, func = actions.get(options.action, None)
    if not func:
        raise PWSafeCLIValidationError("%s is not supported\n" % options.action)

    if validator:
        validator(options)

    if not options.safe_password:
        options.safe_password = getpass("Enter the password for PWSafe3 file: %s\n> " % options.filename)

    func(options)

if __name__ == "__main__": # pragma: no cover
    logging.basicConfig(level = logging.WARNING,
                        format = '%(asctime)s %(levelname)s %(message)s',
                        stream=sys.stderr)
    logger = logging.getLogger('psafe')
    logger.setLevel(logging.WARNING)

    import pypwsafe
    Record = pypwsafe.Record
    PWSafe3 = pypwsafe.PWSafe3

    parsers = makeArgParser()

    try:
        options = parse_commandline(parsers, sys.argv)

        main(options)
    except PWSafeCLIValidationError, e:
        sys.stderr.write("%s\n" % e)
        sys.exit(1)
    except PWSafeCLIError, e:
        sys.stderr.write("%s\n" % e)
        sys.exit(1)
