Summary:	A Secure UDP Tunneling Daemon
Name:		openvpn
Version:	1.1.1.16
Release:	1
URL:		http://sourceforge.net/projects/openvpn/
Source0:	http://prdownloads.sourceforge.net/openvpn/%{name}-%{version}.tar.gz

License:	GPL
Group:		Networking/Tunnels
Vendor:		James Yonan <jim@yonan.net>
Packager:	bishop clark (LC957) <bishop@platypus.bc.ca>
BuildRoot:	%{_tmppath}/%{name}-%(id -un)
Requires:	tun

%description
OpenVPN is a robust and highly flexible tunneling application that
uses all of the encryption, authentication, and certification features
of the OpenSSL library to securely tunnel IP networks over a single
UDP port.

%prep
%setup -q

%build
%configure --enable-pthread
%__make

%install
[ %{buildroot} != "/" ] && rm -rf %{buildroot}
#makeinstall

%__install -c -d -m 755 %{buildroot}%{_mandir}/man8
%__install -c -m 755 %{name}.8 %{buildroot}%{_mandir}/man8
%__install -c -d -m 755 %{buildroot}%{_sbindir}
%__install -c -m 755 %{name} %{buildroot}%{_sbindir}

%__mkdir_p %{buildroot}%{_datadir}/%{name}
%__cp -pr easy-rsa sample-{config-file,key,script}s %{buildroot}%{_datadir}/%{name}

%clean
[ %{buildroot} != "/" ] && rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc AUTHORS COPYING COPYRIGHT.GPL INSTALL NEWS PORTS README 
%{_mandir}/man8/%{name}.8*
%{_sbindir}/%{name}
%{_datadir}/%{name}

%changelog
* Mon May 13 2002 bishop clark (LC957) <bishop@platypus.bc.ca> 1.1.1.14-1
- Added new directories for config examples and such

* Sun May 12 2002 bishop clark (LC957) <bishop@platypus.bc.ca> 1.1.1.13-1
- Updated buildroot directive and cleanup command
- added easy-rsa utilities

* Mon Mar 25 2002 bishop clark (LC957) <bishop@platypus.bc.ca> 1.0-1
- Initial build.
