Summary:	A Secure UDP Tunneling Daemon
Name:		openvpn
Version:	1.0.2
Release:	1
URL:		http://sourceforge.net/projects/openvpn/
Source0:	http://prdownloads.sourceforge.net/openvpn/%{name}-%{version}.tar.gz

License:	GPL
Group:		Networking/Tunnels
Vendor:		James Yonan <jimyonan@users.sourceforge.net>
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
%configure
%__make

%install
# this package does not yet incorporate $(prefix) autoconf bits
#makeinstall

%__install -c -d -m 755 ${RPM_BUILD_ROOT}%{_mandir}/man8
%__install -c -m 755 %{name}.8 ${RPM_BUILD_ROOT}%{_mandir}/man8
%__install -c -d -m 755 ${RPM_BUILD_ROOT}%{_sbindir}
%__install -c -m 755 %{name} ${RPM_BUILD_ROOT}%{_sbindir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc CHANGES COPYING README PORTS {client,server,tmp-ca}.{crt,key} dh1024.pem verify-cn
%{_mandir}/man8/%{name}.8*
%{_sbindir}/%{name}

%changelog
* Mon Mar 25 2002 bishop clark (LC957) <bishop@platypus.bc.ca> 1.0-1
- Initial build.
