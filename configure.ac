#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([pacana],[0.13],[http://github.com/bbidulock/pacana],[pacana],[http://github.com/bbidulock/pacana/issues])
AC_REVISION([0.13])

# set better defaults
AC_PREFIX_DEFAULT([/usr])
if test "$prefix" = /usr -o "$prefix" = NONE; then
	test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc
	test "$sharedstatedir" = '${prefix}/com' && sharedstatedir=/var
	test "$localstatedir" = '${prefix}/var' && localstatedir=/var
fi

AC_CONFIG_SRCDIR([src/pacana.c])
AC_CONFIG_HEADERS([autoconf.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([scripts])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_TARGET

DATE='2021-06-01'
AC_SUBST([DATE])

MDOCDATE='June 1, 2021'
AC_SUBST([MDOCDATE])

BRANCH='0.13'
AC_SUBST([BRANCH])

# Initialize Automake
AM_INIT_AUTOMAKE([gnits 1.16 dist-lzip no-dist-gzip std-options -Wall color-tests silent-rules tar-pax])
AM_MAINTAINER_MODE
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_SED
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AR
AC_PROG_MKDIR_P
AC_ARG_VAR([LD], [Linker loader command])

AC_ARG_VAR([MARKDOWN],[markdown command. @<:@default=markdown@:>@])
AC_CHECK_PROGS([MARKDOWN],[markdown],[${am_missing_run}markdown],[$PATH])

AC_ARG_VAR([ASCIIDOC],[asciidoc command. @<:@default=asciidoctor@:>@])
AC_CHECK_PROGS([ASCIIDOC],[asciidoc asciidoctor],[${am_missing_run}asciidoc],[$PATH])

AC_ARG_VAR([ASCIIDOC_BACKEND],[asciidoc backend @<:@default=NONE@:>@])
if test -z "$ASCIIDOC_BACKEND"; then
	case "$ASCIIDOC" in
		asciidoc) ASCIIDOC_BACKEND="--backend=html4" ;;
		asciidoctor) ASCIIDOC_BACKEND="--backend=html5" ;;
		*) AC_MSG_WARN([ASCIIDOC $ASCIIDOC is not supported.]) ;;
	esac
fi

AC_ARG_VAR([ASCIIMAN],[asciidoc to manpage converter. @<:@default=a2x@:>@])
AC_CHECK_PROGS([ASCIIMAN],[a2x asciidoctor],[${am_missing_run}a2x],[$PATH])

AC_ARG_VAR([ASCIIMAN_FORMAT],[asciidoc manpage option @<:@default=NONE@:>@])
if test -z "$ASCIIMAN_FORMAT"; then
	case "$ASCIIMAN" in
		a2x) ASCIIMAN_FORMAT="--format=manpage" ;;
		asciidoctor) ASCIIMAN_FORMAT="--backend=manpage" ;;
		*) AC_MSG_WARN([ASCIIMAN $ASCIIMAN is not supported.]) ;;
	esac
fi

AC_ARG_VAR([LINKS],[links command. @<:@default=lynx@:>@])
AC_CHECK_PROGS([LINKS],[lynx links],[${am_missing_run}lynx],[$PATH])
if test "$LINKS" = "links"; then
	LINKS="links -codepage utf-8"
fi

AC_DISABLE_STATIC
LT_PATH_LD
LT_PREREQ([2.4.2])
LT_INIT([dlopen])
LT_LANG([C])
AC_SUBST([LIBTOOL_DEPS])

PKG_PROG_PKG_CONFIG([0.14.0])

# Checks for libraries.

# Checks for header files.
AS_BOX([Header Files])
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

dnl AC_PATH_X
dnl AC_PATH_XTRA
AC_CHECK_HEADERS([fcntl.h stdint.h strings.h sys/ioctl.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AS_BOX([Typedefs, Structures, Compiler])
AC_TYPE_SIZE_T

# Checks for library functions.
AS_BOX([Library Functions])
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday setlocale strcasecmp strdup strerror strstr strtoul])

AS_BOX([Extension Libraries])

PKG_CHECK_MODULES([ALPM],[libalpm])
dnl PKG_CHECK_MODULES([X11],[x11])
dnl PKG_CHECK_MODULES([XEXT],[xext])
dnl PKG_CHECK_MODULES([XAU],[xau])
dnl PKG_CHECK_MODULES([XSCRNSAVER],[xscrnsaver])
dnl PKG_CHECK_MODULES([XDMCP],[xdmcp])
dnl PKG_CHECK_MODULES([ICE],[ice])
dnl PKG_CHECK_MODULES([SMLIB],[sm])
dnl PKG_CHECK_MODULES([XFT],[xft])
dnl PKG_CHECK_MODULES([GDK],[gdk-pixbuf-xlib-2.0])
PKG_CHECK_MODULES([GLIB],[glib-2.0])
dnl PKG_CHECK_MODULES([GOBJ],[gobject-2.0])
dnl PKG_CHECK_MODULES([DBUS_GLIB],[dbus-glib-1])
dnl PKG_CHECK_MODULES([GIO],[gio-2.0])
dnl PKG_CHECK_MODULES([GTK],[gtk+-2.0 >= 2.4.0])
dnl PKG_CHECK_MODULES([WNCK],[libwnck-1.0])
dnl PKG_CHECK_MODULES([CAIRO],[cairo])
dnl PKG_CHECK_MODULES([SYSTEMD],[libsystemd])
PKG_CHECK_MODULES([CURL],[libcurl])
PKG_CHECK_MODULES([JSONC],[json-c])

dnl PKG_CHECK_MODULES([GNOME_MENU],[libgnome-menu-3.0],
dnl 		[AC_DEFINE([HAVE_GNOME_MENUS_3],[1],[Define to 1 to support GNOME menus 3.])])
dnl AC_ARG_ENABLE([gnome-menus3],
dnl 	AS_HELP_STRING([--disable-gnome-menus3],[dnl 		Disable GNOME menus 3.0 (use 2.0 instead) @<:@default=auto@:>@]))
dnl if test "x$enable_gnome_menus3" != xno ; then
dnl 	PKG_CHECK_MODULES([GNOME_MENU],[libgnome-menu-3.0],
dnl 		[AC_DEFINE([HAVE_GNOME_MENUS_3],[1],[Define to 1 to support GNOME menus 3.])],
dnl 		[enable_gnome_menus3=no])
dnl fi
dnl AC_MSG_CHECKING([for GNOME MENUS 3 support])
dnl AC_MSG_RESULT([${enable_gnome_menus3:-yes}])
dnl 
dnl if test "x$enable_gnome_menus3" = xno ; then
dnl 	PKG_CHECK_MODULES([GNOME_MENU],[libgnome-menu])
dnl 	PKG_CHECK_MODULES([GIO_UNIX],[gio-unix-2.0])
dnl fi

dnl AC_ARG_ENABLE([xrandr],
dnl 	AS_HELP_STRING([--disable-xrandr],[dnl 		Disable XRANDR support @<:@default=auto@:>@]))
dnl if test "x$enable_xrandr" != xno ; then
dnl 	PKG_CHECK_MODULES([XRANDR],[xrandr],
dnl 		[AC_DEFINE([XRANDR],[1], [Define to 1 to support XRANDR extension.])],
dnl 		[enable_xrandr=no])
dnl fi
dnl AC_MSG_CHECKING([for XRANDR support])
dnl AC_MSG_RESULT([${enable_xrandr:-yes}])

dnl AC_ARG_ENABLE([xinerama],
dnl 	AS_HELP_STRING([--disable-xinerama],[dnl 		Disable XINERAMA support @<:@default=auto@:>@]))
dnl if test "x$enable_xinerama" != xno ; then
dnl 	PKG_CHECK_MODULES([XINERAMA],[xinerama],
dnl 		[AC_DEFINE([XINERAMA],[1], [Define to 1 to support XINERAMA extension.])],
dnl 		[enable_xinerama=no])
dnl fi
dnl AC_MSG_CHECKING([for XINERAMA support])
dnl AC_MSG_RESULT([${enable_xinerama:-yes}])

AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug],[Enable debugging support @<:@default=disabled@:>@]))
if test "x$enable_debug" = xyes ; then
	AC_DEFINE_UNQUOTED([DEBUG],[],[Define to enable debugging])
fi
AC_MSG_CHECKING([for debug support])
AC_MSG_RESULT([${enable_debug:-no}])

test "x$prefix" = xNONE && prefix="$ac_default_prefix"
sharedir="$datadir"
eval "sharedir=\"$sharedir\""
eval "sharedir=\"$sharedir\""
eval "sharedir=\"$sharedir\""
AC_SUBST([sharedir])

xdgconfdir="$sysconfdir"
eval "xdgconfdir=\"$xdgconfdir\""
eval "xdgconfdir=\"$xdgconfdir\""
eval "xdgconfdir=\"$xdgconfdir\""
AC_SUBST([xdgconfdir])

xdgdatadir="$prefix"
eval "xdgdatadir=\"$xdgdatadir\""
eval "xdgdatadir=\"$xdgdatadir\""
eval "xdgdatadir=\"$xdgdatadir\""
AC_SUBST([xdgdatadir])

xdemoddir='${libdir}/xde-menu/modules'
AC_SUBST([xdemoddir])

autostartdir='$(xdgconfdir)/xdg/autostart'
AC_SUBST([autostartdir])

applicationsdir='$(xdgdatadir)/share/applications'
AC_SUBST([applicationsdir])

appdefaultsdir='$(sharedir)/X11/app-defaults'
AC_SUBST([appdefaultsdir])

AC_CONFIG_FILES([Makefile
                 man/Makefile
                 src/Makefile])
AC_OUTPUT

# vim: set ft=config:
