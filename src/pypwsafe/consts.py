#===============================================================================
# SYMANTEC:     Copyright (C) 2009-2011 Symantec Corporation. All rights reserved.
#
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
''' PSafe constants
Created on Oct 27, 2010

@author: mcintyrep
'''

#                Configuration options
#            Configuration Statics
ptApplication = 0
ptDatabase = 1
ptObsolete = 2

#            Bools
conf_bools = {
    'AlwaysOnTop':{
        'default':False,
        'type':ptApplication,
        'name':'AlwaysOnTop',
        'index':0
    },

    'ShowPWDefault':{
        'default':False,
        'type':ptDatabase,
        'name':'ShowPWDefault',
        'index':1
    },

    'ShowPasswordInTree':{
        'default':False,
        'type':ptDatabase,
        'name':'ShowPasswordInTree',
        'index':2
    },

    'SortAscending':{
        'default':True,
        'type':ptDatabase,
        'name':'SortAscending',
        'index':3
    },

    'UseDefaultUser':{
        'default':False,
        'type':ptDatabase,
        'name':'UseDefaultUser',
        'index':4
    },

    'SaveImmediately':{
        'default':True,
        'type':ptDatabase,
        'name':'SaveImmediately',
        'index':5
    },

    'PWUseLowercase':{
        'default':True,
        'type':ptDatabase,
        'name':'PWUseLowercase',
        'index':6
    },

    'PWUseUppercase':{
        'default':True,
        'type':ptDatabase,
        'name':'PWUseUppercase',
        'index':7
    },

    'PWUseDigits':{
        'default':True,
        'type':ptDatabase,
        'name':'PWUseDigits',
        'index':8
    },

    'PWUseSymbols':{
        'default':False,
        'type':ptDatabase,
        'name':'PWUseSymbols',
        'index':9
    },

    'PWUseHexDigits':{
        'default':False,
        'type':ptDatabase,
        'name':'PWUseHexDigits',
        'index':10
    },

    'PWUseEasyVision':{
        'default':False,
        'type':ptDatabase,
        'name':'PWUseEasyVision',
        'index':11
    },

    'dontaskquestion':{
        'default':False,
        'type':ptApplication,
        'name':'dontaskquestion',
        'index':12
    },

    'deletequestion':{
        'default':False,
        'type':ptApplication,
        'name':'deletequestion',
        'index':13
    },

    'DCShowsPassword':{
        'default':False,
        'type':ptApplication,
        'name':'DCShowsPassword',
        'index':14
    },

    'DontAskMinimizeClearYesNo':{
        'default':True,
        'type':ptObsolete,
        'name':'DontAskMinimizeClearYesNo',
        'index':15
    },

    'DatabaseClear':{
        'default':False,
        'type':ptApplication,
        'name':'DatabaseClear',
        'index':16
    },

    'DontAskSaveMinimize':{
        'default':False,
        'type':ptObsolete,
        'name':'DontAskSaveMinimize',
        'index':17
    },

    'QuerySetDef':{
        'default':True,
        'type':ptApplication,
        'name':'QuerySetDef',
        'index':18
    },

    'UseNewToolbar':{
        'default':True,
        'type':ptApplication,
        'name':'UseNewToolbar',
        'index':19
    },

    'UseSystemTray':{
        'default':True,
        'type':ptApplication,
        'name':'UseSystemTray',
        'index':20
    },

    'LockOnWindowLock':{
        'default':True,
        'type':ptApplication,
        'name':'LockOnWindowLock',
        'index':21
    },

    'LockOnIdleTimeout':{
        'default':True,
        'type':ptObsolete,
        'name':'LockOnIdleTimeout',
        'index':22
    },

    'EscExits':{
        'default':True,
        'type':ptApplication,
        'name':'EscExits',
        'index':23
    },

    'IsUTF8':{
        'default':False,
        'type':ptDatabase,
        'name':'IsUTF8',
        'index':24
    },

    'HotKeyEnabled':{
        'default':False,
        'type':ptApplication,
        'name':'HotKeyEnabled',
        'index':25
    },

    'MRUOnFileMenu':{
        'default':True,
        'type':ptApplication,
        'name':'MRUOnFileMenu',
        'index':26
    },

    'DisplayExpandedAddEditDlg':{
        'default':True,
        'type':ptObsolete,
        'name':'DisplayExpandedAddEditDlg',
        'index':27
    },

    'MaintainDateTimeStamps':{
        'default':False,
        'type':ptDatabase,
        'name':'MaintainDateTimeStamps',
        'index':28
    },

    'SavePasswordHistory':{
        'default':False,
        'type':ptDatabase,
        'name':'SavePasswordHistory',
        'index':29
    },

    'FindWraps':{
        'default':False,
        'type':ptObsolete,
        'name':'FindWraps',
        'index':30
    },

    'ShowNotesDefault':{
        'default':False,
        'type':ptDatabase,
        'name':'ShowNotesDefault',
        'index':31
    },

    'BackupBeforeEverySave':{
        'default':True,
        'type':ptApplication,
        'name':'BackupBeforeEverySave',
        'index':32
    },

    'PreExpiryWarn':{
        'default':False,
        'type':ptApplication,
        'name':'PreExpiryWarn',
        'index':33
    },

    'ExplorerTypeTree':{
        'default':False,
        'type':ptApplication,
        'name':'ExplorerTypeTree',
        'index':34
    },

    'ListViewGridLines':{
        'default':False,
        'type':ptApplication,
        'name':'ListViewGridLines',
        'index':35
    },

    'MinimizeOnAutotype':{
        'default':True,
        'type':ptApplication,
        'name':'MinimizeOnAutotype',
        'index':36
    },

    'ShowUsernameInTree':{
        'default':True,
        'type':ptDatabase,
        'name':'ShowUsernameInTree',
        'index':37
    },

    'PWMakePronounceable':{
        'default':False,
        'type':ptDatabase,
        'name':'PWMakePronounceable',
        'index':38
    },

    'ClearClipoardOnMinimize':{
        'default':True,
        'type':ptObsolete,
        'name':'ClearClipoardOnMinimize',
        'index':39
    },

    'ClearClipoardOneExit':{
        'default':True,
        'type':ptObsolete,
        'name':'ClearClipoardOneExit',
        'index':40
    },

    'ShowToolbar':{
        'default':True,
        'type':ptApplication,
        'name':'ShowToolbar',
        'index':41
    },

    'ShowNotesAsToolTipsInViews':{
        'default':False,
        'type':ptApplication,
        'name':'ShowNotesAsToolTipsInViews',
        'index':42
    },

    'DefaultOpenRO':{
        'default':False,
        'type':ptApplication,
        'name':'DefaultOpenRO',
        'index':43
    },

    'MultipleInstances':{
        'default':True,
        'type':ptApplication,
        'name':'MultipleInstances',
        'index':44
    },

    'ShowDragbar':{
        'default':True,
        'type':ptApplication,
        'name':'ShowDragbar',
        'index':45
    },

    'ClearClipboardOnMinimize':{
        'default':True,
        'type':ptApplication,
        'name':'ClearClipboardOnMinimize',
        'index':46
    },

    'ClearClipboardOnExit':{
        'default':True,
        'type':ptApplication,
        'name':'ClearClipboardOnExit',
        'index':47
    },

    'ShowFindToolBarOnOpen':{
        'default':False,
        'type':ptApplication,
        'name':'ShowFindToolBarOnOpen',
        'index':48
    },

    'NotesWordWrap':{
        'default':False,
        'type':ptApplication,
        'name':'NotesWordWrap',
        'index':49
    },

    'LockDBOnIdleTimeout':{
        'default':True,
        'type':ptDatabase,
        'name':'LockDBOnIdleTimeout',
        'index':50
    },

    'HighlightChanges':{
        'default':True,
        'type':ptApplication,
        'name':'HighlightChanges',
        'index':51
    },

    'HideSystemTray':{
        'default':False,
        'type':ptApplication,
        'name':'HideSystemTray',
        'index':52
    },
}

#            Ints
conf_ints = {
    'column1width':{
        'name':'column1width',
        'default':65535,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':0,
    },

    'column2width':{
        'name':'column2width',
        'default':65535,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':1,
    },

    'column3width':{
        'name':'column3width',
        'default':65535,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':2,
    },

    'column4width':{
        'name':'column4width',
        'default':65535,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':3,
    },

    'sortedcolumn':{
        'name':'sortedcolumn',
        'default':0,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':4,
    },

    'PWDefaultLength':{
        'name':'PWDefaultLength',
        'default':8,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':5,
    },

    'maxmruitems':{
        'name':'maxmruitems',
        'default':4,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':6,
    },

    'IdleTimeout':{
        'name':'IdleTimeout',
        'default':5,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':7,
    },

    'DoubleClickAction':{
        'name':'DoubleClickAction',
        'default':0,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':8,
    },

    'HotKey':{
        'name':'HotKey',
        'default':0,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':9,
    },

    'MaxREItems':{
        'name':'MaxREItems',
        'default':25,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':10,
    },

    'TreeDisplayStatusAtOpen':{
        'name':'TreeDisplayStatusAtOpen',
        'default':0,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':11,
    },

    'NumPWHistoryDefault':{
        'name':'NumPWHistoryDefault',
        'default':3,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':12,
    },

    'BackupSuffix':{
        'name':'BackupSuffix',
        'default':0,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':13,
    },

    'BackupMaxIncremented':{
        'name':'BackupMaxIncremented',
        'default':1,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':14,
    },

    'PreExpiryWarnDays':{
        'name':'PreExpiryWarnDays',
        'default':1,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':15,
    },

    'ClosedTrayIconColour':{
        'name':'ClosedTrayIconColour',
        'default':0,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':16,
    },

    'PWDigitMinLength':{
        'name':'PWDigitMinLength',
        'default':0,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':17,
    },

    'PWLowercaseMinLength':{
        'name':'PWLowercaseMinLength',
        'default':0,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':18,
    },

    'PWSymbolMinLength':{
        'name':'PWSymbolMinLength',
        'default':0,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':19,
    },

    'PWUppercaseMinLength':{
        'name':'PWUppercaseMinLength',
        'default':0,
        'type':ptDatabase,
        'min':-1,
        'max':-1,
        'index':20,
    },

    'OptShortcutColumnWidth':{
        'name':'OptShortcutColumnWidth',
        'default':92,
        'type':ptApplication,
        'min':-1,
        'max':-1,
        'index':21,
    },
}

#            Strings
conf_strs = {
    'currentbackup':{
        'name':'currentbackup',
        'default':'',
        'type':ptApplication,
        'index':0,
    },

    'currentfile':{
        'name':'currentfile',
        'default':'',
        'type':ptApplication,
        'index':1,
    },

    'lastview':{
        'name':'lastview',
        'default':'tree',
        'type':ptApplication,
        'index':2,
    },

    'DefaultUsername':{
        'name':'DefaultUsername',
        'default':'',
        'type':ptDatabase,
        'index':3,
    },

    'treefont':{
        'name':'treefont',
        'default':'',
        'type':ptApplication,
        'index':4,
    },

    'BackupPrefixValue':{
        'name':'BackupPrefixValue',
        'default':'',
        'type':ptApplication,
        'index':5,
    },

    'BackupDir':{
        'name':'BackupDir',
        'default':'',
        'type':ptApplication,
        'index':6,
    },

    'AltBrowser':{
        'name':'AltBrowser',
        'default':'',
        'type':ptApplication,
        'index':7,
    },

    'ListColumns':{
        'name':'ListColumns',
        'default':'',
        'type':ptApplication,
        'index':8,
    },

    'ColumnWidths':{
        'name':'ColumnWidths',
        'default':'',
        'type':ptApplication,
        'index':9,
    },

    'DefaultAutotypeString':{
        'name':'DefaultAutotypeString',
        'default':'',
        'type':ptDatabase,
        'index':10,
    },

    'AltBrowserCmdLineParms':{
        'name':'AltBrowserCmdLineParms',
        'default':'',
        'type':ptApplication,
        'index':11,
    },

    'MainToolBarButtons':{
        'name':'MainToolBarButtons',
        'default':'',
        'type':ptApplication,
        'index':12,
    },

    'PasswordFont':{
        'name':'PasswordFont',
        'default':'',
        'type':ptApplication,
        'index':13,
    },

    'TreeListSampleText':{
        'name':'TreeListSampleText',
        'default':'AaBbYyZz 0O1IlL',
        'type':ptApplication,
        'index':14,
    },

    'PswdSampleText':{
        'name':'PswdSampleText',
        'default':'AaBbYyZz 0O1IlL',
        'type':ptApplication,
        'index':15,
    },

    'LastUsedKeyboard':{
        'name':'LastUsedKeyboard',
        'default':'',
        'type':ptApplication,
        'index':16,
    },

    'VKeyboardFontName':{
        'name':'VKeyboardFontName',
        'default':'',
        'type':ptApplication,
        'index':17,
    },

    'VKSampleText':{
        'name':'VKSampleText',
        'default':'AaBbYyZz 0O1IlL',
        'type':ptApplication,
        'index':18,
    },

    'AltNotesEditor':{
        'name':'AltNotesEditor',
        'default':'',
        'type':ptApplication,
        'index':19,
    },
}

#           Type Mappings
conf_types = {}
for name, info in conf_bools.items():
    conf_types[name] = bool
for name, info in conf_ints.items():
    conf_types[name] = int
for name, info in conf_strs.items():
    conf_types[name] = str



