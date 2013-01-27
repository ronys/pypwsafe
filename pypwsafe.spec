Name:		pypwsafe
Summary:	A Python library program for reading Password Safe files.  

Group:		Applications/Internet
License:	GPLv2
URL:		https://github.com/ronys/pypwsafe
Source0:	%{name}-%{version}-%{release}.tgz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires:	%{name}-lib = %{version}-%{release}

%package lib
Summary: 	A Python library for reading and writing Password Safe files.
Group: 		Development/Libraries
Requires:	python-mcrypt
Requires:	python >= 2.4

%package webui
Summary: 	A Django-based web UI and RPC layer for interacting with one or more Password Safe files. 
Group: 		Applications/Internet
Requires:	Django >= 1.3
Requires:	python-mcrypt
Requires:	python >= 2.4
# Not avail as RPMs yet
#Requires:	django-dajax
#Requires:	django-dajaxice
#Requires:	django-rpc4django

%description
FIXME

%description webui
FIXME

%description lib
FIXME

%prep
%setup -q


%build


%install
rm -rf %{buildroot}
/usr/bin/python setup.py install --root=%{buildroot}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc
/usr/bin/psafedump

%files lib
%dir /usr/lib/python2.6/site-packages/pypwsafe/
/usr/lib/python2.6/site-packages/pypwsafe/__init__.py*
/usr/lib/python2.6/site-packages/pypwsafe/consts.py*
/usr/lib/python2.6/site-packages/pypwsafe/errors.py*
/usr/lib/python2.6/site-packages/pypwsafe/PWSafeV3Headers.py*
/usr/lib/python2.6/site-packages/pypwsafe/PWSafeV3Records.py*
%exclude /usr/lib/python2.6/site-packages/python_pypwsafe-*-py2.6.egg-info

%files webui
/usr/lib/python2.6/site-packages/psafefe/*.py*
/usr/lib/python2.6/site-packages/psafefe/pws/*.py*
/usr/lib/python2.6/site-packages/psafefe/pws/rpc/*.py*
/usr/lib/python2.6/site-packages/psafefe/pws/tasks/*.py*

/usr/share/psafefe/media/README
/usr/share/psafefe/static/base.css
%exclude /usr/share/psafefe/static/.gitignore
/usr/share/psafefe/templates/*html
/usr/share/psafefe/templates/registration/*html

%changelog
* Wed Jul 18 2012 Paulson McIntyre <paul@gpmidi.net> - 0.0-0
- Initial version
