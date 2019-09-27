AM_CFLAGS = $(DEBUG_CFLAGS)

bin_PROGRAMS = \
	pacana

EXTRA_PROGRAMS =

pacana_CPPFLAGS = -DNAME=\"pacana\"
pacana_CFLAGS = $(AM_CFLAGS) $(ALPM_CFLAGS)
pacana_SOURCES = pacana.c
pacana_LDADD = $(ALPM_LIBS)

dist_bin_SCRIPTS =

AM_INSTALLCHECK_STD_OPTIONS_EXEMPT = pacana

