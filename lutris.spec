%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

Name:           lutris
Version:        0.3.7
Release:        2%{?dist}
Summary:        Install and play any video game easily

License:        GPLv3+
URL:            http://lutris.net
Source0:        http://lutris.net/releases/lutris_%{version}.tar.gz

BuildArch:      noarch

# Common build dependencies
BuildRequires:  desktop-file-utils
BuildRequires:  python-devel

%if 0%{?fedora_version}
BuildRequires:  pygobject3
Requires:       pygobject3, PyYAML
%endif
%if 0%{?rhel_version} || 0%{?centos_version}
BuildRequires:  pygobject3
Requires:       pygobject3, PyYAML
%endif
%if 0%{?suse_version}
BuildRequires:  python-gobject
BuildRequires:  update-desktop-files
Requires:       python-gobject, python-gtk, python-PyYAML
%endif


%description
Lutris is a gaming platform for GNU/Linux. Its goal is to make
gaming on Linux as easy as possible by taking care of installing
and setting up the game for the user. The only thing you have to
do is play the game. It aims to support every game that is playable
on Linux.

%prep
%setup -q -n %{name}


%build
%{__python} setup.py build


%install
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT

#desktop icon
%if 0%{?suse_version}
%suse_update_desktop_file -r -i %{name} Network FileTransfer
%endif

%if 0%{?fedora_version} || 0%{?rhel_version} || 0%{?centos_version}
desktop-file-install --dir=$RPM_BUILD_ROOT%{_datadir}/applications %{name}.desktop
desktop-file-validate %{buildroot}%{_datadir}/applications/%{name}.desktop
%endif

%files
%dir %{_datadir}/glib-2.0
%dir %{_datadir}/glib-2.0/schemas
%dir %{_datadir}/icons
%dir %{_datadir}/icons/hicolor
%dir %{_datadir}/icons/hicolor/scalable
%dir %{_datadir}/icons/hicolor/scalable/apps
%dir %{_datadir}/polkit-1
%dir %{_datadir}/polkit-1/actions
%{_bindir}/lutris
%{_datadir}/applications/%{name}.desktop
%{_datadir}/glib-2.0/schemas/apps.%{name}.gschema.xml
%{_datadir}/icons/hicolor/scalable/apps/%{name}.svg
%{_datadir}/lutris/
%{_datadir}/pixmaps/%{name}.png
%{_datadir}/polkit-1/actions/*
%{python_sitelib}/%{name}-%{version}-py2.7.egg-info
%{python_sitelib}/lutris/


%changelog
* Sat Dec 12 2015 Rémi Verschelde <akien@mageia.org> - 0.3.7-2
- Spec file cleanup

* Fri Nov 27 2015 Mathieu Comandon <strycore@gmail.com> - 0.3.7-1
- Bump to version 0.3.7

* Thu Oct 30 2014 Mathieu Comandon <strycore@gmail.com> - 0.3.6-1
- Bump to version 0.3.6
- Add OpenSuse compatibility (contribution by @malkavi)

* Fri Sep 12 2014 Mathieu Comandon <strycore@gmail.com> - 0.3.5-1
- Bump version to 0.3.5

* Thu Aug 14 2014 Travis Nickles <nickles.travis@gmail.com> - 0.3.4-3
- Edited Requires to include pygobject3.

* Wed Jun 04 2014 Travis Nickles <nickles.travis@gmail.com> - 0.3.4-2
- Changed build and install step based on template generated by
  rpmdev-newspec.
- Added Requires.
- Ensure package can be built using mock.

* Tue Jun 03 2014 Travis Nickles <nickles.travis@gmail.com> - 0.3.4-1
- Initial version of the package
