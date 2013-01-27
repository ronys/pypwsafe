#!/usr/bin/python

import copy
from mock import Mock
from nose.tools import assert_equals
import optparse
import os
import sys

import pwsafecli

# available in newer versions
class AssertRaises(object):
    def __init__(self, exception):
        self.expected_exception = exception
        self.exception = None

    def __enter__(self):
        pass

    def __exit__(self, exctype, value, tb):
        assert_equals(exctype, self.expected_exception)

        self.exception = exctype(value)
        return True

def test_get_record_attr():
    record = Mock(spec=["getFoo", "getBar"])
    record.getFoo = Mock(return_value="foo")
    record.getBar = Mock(return_value=False)

    assert_equals("foo", pwsafecli.get_record_attr(record, "foo"))
    assert_equals(False, pwsafecli.match_valid(record, **{}))
    assert_equals(True, pwsafecli.match_valid(record, **{"foo": "foo"}))
    assert_equals(True, pwsafecli.match_valid(record, **{"foo": "foo", "title": None}))
    assert_equals(False, pwsafecli.match_valid(record, **{"foo": "foo", "bar": True}))
    with AssertRaises(AttributeError):
        pwsafecli.match_valid(record, **{"waz": object()})

def try_collect_record_options_with_attrs(attrs):
    mock = Mock(spec=["group", "title", "username", "UUID"])
    mock.group = None
    mock.title = None
    mock.username = None
    mock.UUID = None
    for key in attrs.keys():
        setattr(mock, key, attrs[key])

    result = pwsafecli.collect_record_options(mock)
    assert_equals(attrs, result)

def test_collect_record_options():
    try_collect_record_options_with_attrs({})
    try_collect_record_options_with_attrs({"group": ['foo']})
    try_collect_record_options_with_attrs({'title': 'Test Node'})
    try_collect_record_options_with_attrs({'username': 'bob'})
    try_collect_record_options_with_attrs({'UUID': '1-1-1-1'})

class TestCommandLine(object):
    def __init__(self):
        self.parsers = pwsafecli.makeArgParser()
        self.orig_stderr = copy.deepcopy(sys.stderr)
        sys.stderr = open(os.devnull, "wb")
        self.orig_stdout = copy.deepcopy(sys.stdout)
        sys.stdout = open(os.devnull, "wb")

    def __del__(self):
        sys.stdout = self.orig_stdout
        sys.stderr = self.orig_stderr

    def test_no_action(self):
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.parse_commandline(self.parsers, ['unittest',])

    def test_no_action_help(self):
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.parse_commandline(self.parsers, "unittest --help".split())

    def test_unknown(self):
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.parse_commandline(self.parsers, "unittest --what".split())

    def test_unknown_command(self):
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.parse_commandline(self.parsers,
                                       "unittest unknown".split())

    def test_add_no_options(self):
        with AssertRaises(SystemExit) as cm:
            options = pwsafecli.parse_commandline(self.parsers,
                                                 "unittest add".split())

    def test_add_filename_no_options(self):
        options = pwsafecli.parse_commandline(self.parsers,
                                             "unittest add --file foo".split())
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.add_validator(options)

    def test_add_missing_password(self):
        options = pwsafecli.parse_commandline(self.parsers,
                                             "unittest add --file foo --title blah --username me --group foo.bar.baz".split())
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.add_validator(options)

    def test_add_expires_option(self):
        options = pwsafecli.parse_commandline(self.parsers,
                                             ["unittest", "add", "--file", "foo", "--title", "blah", "--username", "me", "--group", "foo.bar.baz", "--password", "secret", "--expires", "2012-01-01 00:00"])
        pwsafecli.add_validator(options)

        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            options = pwsafecli.parse_commandline(self.parsers,
                                                 ["unittest", "add", "--file", "foo", "--title", "blah", "--username", "me", "--group", "foo.bar.baz", "--password", "secret", "--expires", "2012-01-01 00:00:00 MDT"])

    def test_delete_missing_uuid(self):
        options = pwsafecli.parse_commandline(self.parsers,
                                             "unittest delete --file foo".split())
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.delete_validator(options)

    def test_get_missing_options(self):
        for cmdline in ("unittest get --file foo", "unittest get --file foo --email foo@bar"):
            print cmdline
            options = pwsafecli.parse_commandline(self.parsers,
                                                 cmdline.split())
            with AssertRaises(pwsafecli.PWSafeCLIValidationError):
                pwsafecli.get_validator(options)

    def test_get_display_option(self):
        options = pwsafecli.parse_commandline(self.parsers, "unittest get --file foo --uuid f2dee5f8-e964-402f-9fe7-78bd2b5cba2e --display username,password".split())
        pwsafecli.get_validator(options)

        options = pwsafecli.parse_commandline(self.parsers, "unittest get --file foo --uuid f2dee5f8-e964-402f-9fe7-78bd2b5cba2e --display username,password,uuid".split())
        pwsafecli.get_validator(options)

        options = pwsafecli.parse_commandline(self.parsers, "unittest get --file foo --uuid f2dee5f8-e964-402f-9fe7-78bd2b5cba2e --display username,password,uuid,missing".split())

        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.get_validator(options)

    def test_init_options(self):
        options = pwsafecli.parse_commandline(self.parsers, "unittest init --file foo".split())
        pwsafecli.init_validator(options)

    def test_update_missing_uuid(self):
        options = pwsafecli.parse_commandline(self.parsers,
                                             "unittest update --file foo --username test".split())
        with AssertRaises(pwsafecli.PWSafeCLIValidationError) as cm:
            pwsafecli.update_validator(options)
