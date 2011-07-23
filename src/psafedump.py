#!/usr/bin/python
''' A CLI interface for PyPWSafe. 

Allow users to view Password Safe files. 

Created on Jul 22, 2011

@author: paulson mcintyre <paul@gpmidi.net>
@author: steve <rader@hep.wisc.edu>
'''
import logging, logging.config
logger = logging.getLogger("psafebin.dump")
log = logger.log
logging.basicConfig(
                    level = logging.INFO,
                    format = '%(asctime)s %(levelname)s %(message)s',
                    )
log(10, 'initing')
import os, sys, os.path
# FIXME: Add in tests to make sure we can import all 
# required libraries and generate non-coder errors
# as to what is missing. 
#try:
import pypwsafe as pws
#except ImportError:
#    log(50, "Can't find the pypwsafe library")
#    sys.exit(1)
    
from optparse import OptionParser

# TODO: Find a simpler way of doing this
def show_entry(entry, opts):
    """ Return true if an entry should be displayed """
    m = (
       ('Group', opts.filter_group),
       ('UUID', opts.filter_uuid),
       ('Title', opts.filter_title),
       ('Username', opts.filter_username),
       )
    def match(e_name, lst):
        """ Return true if the given entry properity, 
        e_name, is in lst or lst is empty. 
        """
        if len(lst) > 0:
            if entry[e_name] in lst:
                return True
            else:
                return False
        else:
            return True
    
    for e_name, lst in m:
        if not match(e_name, lst):
            return False
        
    return True
    
def display_xml(entries, opts):
    raise NotImplementedError

def display_csv(entries, opts):
    ret = ''
    by_groups = {}
    for entry in entries:
        group = '.'.join(entry['Group'])
        if not by_groups.has_key(group):
            by_groups[group] = []
        by_groups[group].append(entry)
    groups = by_groups.keys()
    groups.sort()
    for group in groups:
        by_groups[group].sort(lambda a, b: cmp(a['Title'] + a['Username'], b['Title'] + b['Username']))
        for entry in by_groups[group]:
            ret += "%r, " % group
            ret += """%(Title)r, %(Username)r, %(Password)r\n""" % entry
    return ret

def display_display(entries, opts):
    ret = ''
    by_groups = {}
    for entry in entries:
        group = '.'.join(entry['Group'])
        if not by_groups.has_key(group):
            by_groups[group] = []
        by_groups[group].append(entry)
    groups = by_groups.keys()
    # In place!
    groups.sort()
    for group in groups:
        ret += "= %r =\n" % group
        by_groups[group].sort(lambda a, b: cmp(a['Title'] + a['Username'], b['Title'] + b['Username']))
        for entry in by_groups[group]:
            ret += """    == %(Title)r ==
        Username: %(Username)r
        Password: %(Password)r
""" % entry
    return ret
        
    
if __name__ == "__main__":
    # Setup option parser to parse out args
    parser = OptionParser(
                          usage = "%prog",
                          version = "%prog v0.1",
                          prog = "psafedump",
                          description = """
A CLI interface for viewing Password Safe files.                       
                          """,
                          )
    # TODO: Support multiple files
    parser.add_option(
                      "-f",
                      "--file",
                      action = "store",
                      type = "string",
                      dest = "filename",
                      default = None,
                      help = "Password Safe file to create, edit, or view. ",
                      )
    parser.add_option(
                      "-r",
                      "--readonly",
                      action = "store_true",
                      dest = "readonly",
                      default = False,
                      help = "Open the Password Safe in read-only mode. [Default: %default]",
                      )
    parser.add_option(
                      "-p",
                      "--password",
                      action = "append",
                      dest = "password",
                      default = [],
                      help = "The password to use when opening the file. If given multiple times each password given will be tried. If not given, a password will be prompted for via STDIN and STDOUT. Note: Specifying the password via an argument is INSECURE. ",
                      )
    parser.add_option(
                      "-d",
                      "--debug",
                      action = "store_true",
                      dest = "debug",
                      default = False,
                      help = "Run in debug mode. Running in this mode WILL EXPOSE YOUR PASSWORDS and other sensitive information. [Default: %default]",
                      )
    # Output format
    parser.add_option(
                      "--xml",
                      action = "store_true",
                      default = False,
                      dest = "xml",
                      help = "Display results in XML",
                      )
    parser.add_option(
                      "--csv",
                      action = "store_true",
                      default = False,
                      dest = "csv",
                      help = "Display results in CSV",
                      )
    parser.add_option(
                      "--display",
                      action = "store_true",
                      default = False,
                      dest = "display",
                      help = "Display results in a human readable format",
                      )
    
    # Display Filters
    parser.add_option(
                      "--uuid",
                      action = "append",
                      dest = "filter_uuid",
                      default = [],
                      help = "Limit display to entries with this UUID. If given multiple times then displayed entries must match at least one of the UUIDs. ",
                      )
    parser.add_option(
                      "--title",
                      action = "append",
                      dest = "filter_title",
                      default = [],
                      help = "Limit display to entries with this title. If given multiple times then displayed entries must match at least one of the titles. ",
                      )
    parser.add_option(
                      "--group",
                      action = "append",
                      dest = "filter_group",
                      default = [],
                      help = "Limit display to entries with this group. If given multiple times then displayed entries must match at least one of the groups. ",
                      )
    parser.add_option(
                      "--username",
                      action = "append",
                      dest = "filter_username",
                      default = [],
                      help = "Limit display to entries with this username. If given multiple times then displayed entries must match at least one of the usernames. ",
                      )
    log(10, "Parsing args")
    (opts, args) = parser.parse_args()
    
    if opts.debug:
        logger.setLevel(logging.DEBUG)
    
    # Handle filename as first arg
    if not opts.filename:
        if len(args) == 1:
            opts.filename = args[0]
        else:
            log(50, "No filename was given")
            parser.error("No filename specified. ")
            sys.exit(2)
    
    # FIXME: Add tests to make sure that
    #    - File exists (reading)
    #    - File doesn't exist but can create it (creating)
    #    - Can write the file if not readonly
    
    if not (opts.xml or opts.csv or opts.display):
        opts.display = True
        log(10, "No output format given. Defaulting to display.")
        
    if len(opts.password) == 0:
        # FIXME: Add in support for prompting for a password. 
        raise NotImplementedError
    
    if opts.readonly:
        mode = "RO"
    else:
        mode = "RW"
    log(10, "Set mode to %r", mode)
    
    psafe = None
    for passwd in opts.password:
        try:
            log(10, "Trying password %r", passwd)
            psafe = pws.PWSafe3(
                                filename = opts.filename,
                                password = passwd,
                                mode = mode,
                                )
            log(10, "Got psafe object %r", psafe)
            break
        except pws.PasswordError:
            log(10, "Password error - Trying next password if any")
            continue
    
    if not psafe:
        log(50, "No valid password was found. ")

    to_display = []
    for entry in psafe.records:
        if show_entry(entry, opts):
            to_display.append(entry)

    if opts.xml:
        print display_xml(to_display, opts)
    elif opts.csv:
        print display_csv(to_display, opts)
    elif opts.display:
        print display_display(to_display, opts)    
    
