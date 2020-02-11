/*****************************************************************************

 Copyright (c) 2010-2019  Monavacon Limited <http://www.monavacon.com/>
 Copyright (c) 2002-2009  OpenSS7 Corporation <http://www.openss7.com/>
 Copyright (c) 1997-2001  Brian F. G. Bidulock <bidulock@openss7.org>

 All Rights Reserved.

 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, version 3 of the license.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 details.

 You should have received a copy of the GNU General Public License along with
 this program.  If not, see <http://www.gnu.org/licenses/>, or write to the
 Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 -----------------------------------------------------------------------------

 U.S. GOVERNMENT RESTRICTED RIGHTS.  If you are licensing this Software on
 behalf of the U.S. Government ("Government"), the following provisions apply
 to you.  If the Software is supplied by the Department of Defense ("DoD"), it
 is classified as "Commercial Computer Software" under paragraph 252.227-7014
 of the DoD Supplement to the Federal Acquisition Regulations ("DFARS") (or any
 successor regulations) and the Government is acquiring only the license rights
 granted herein (the license rights customarily provided to non-Government
 users).  If the Software is supplied to any unit or agency of the Government
 other than DoD, it is classified as "Restricted Computer Software" and the
 Government's rights in the Software are defined in paragraph 52.227-19 of the
 Federal Acquisition Regulations ("FAR") (or any successor regulations) or, in
 the cases of NASA, in paragraph 18.52.227-86 of the NASA Supplement to the FAR
 (or any successor regulations).

 -----------------------------------------------------------------------------

 Commercial licensing and support of this software is available from OpenSS7
 Corporation at a fee.  See http://www.openss7.com/

 *****************************************************************************/

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

/** @section Includes
  * @{ */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#ifdef _GNU_SOURCE
#include <getopt.h>
#endif
#include <time.h>
#include <signal.h>
#include <syslog.h>
#include <sys/utsname.h>

#include <assert.h>
#include <locale.h>
#include <stdarg.h>
#include <strings.h>
#include <regex.h>
#include <wordexp.h>
#include <execinfo.h>

#include <alpm.h>
#include <glib.h>

/** @} */

/** @section Debugging Preamble
  * @{ */

const char *
_timestamp(void)
{
	static struct timeval tv = { 0, 0 };
	static struct tm tm = { 0, };
	static char buf[BUFSIZ];
	size_t len;

	gettimeofday(&tv, NULL);
	len = strftime(buf, sizeof(buf) - 1, "%b %d %T", gmtime_r(&tv.tv_sec, &tm));
	snprintf(buf + len, sizeof(buf) - len - 1, ".%06ld", tv.tv_usec);
	return buf;
}

#define XPRINTF(_args...) do { } while (0)

#define DPRINTF(_num, _args...) do { if (options.debug >= _num) { \
		fprintf(stderr, NAME "[%d]: D: [%s] %12s: +%4d : %s() : ", getpid(), _timestamp(), __FILE__, __LINE__, __func__); \
		fprintf(stderr, _args); fflush(stderr); } } while (0)

#define EPRINTF(_args...) do { \
		fprintf(stderr, NAME "[%d]: E: [%s] %12s +%4d : %s() : ", getpid(), _timestamp(), __FILE__, __LINE__, __func__); \
		fprintf(stderr, _args); fflush(stderr); } while (0)

#define WPRINTF(_args...) do { \
		fprintf(stderr, "W: "); \
		fprintf(stderr, _args); fflush(stderr); } while (0)

#define IPRINTF(_args...) do { \
		fprintf(stdout, "I: "); \
		fprintf(stdout, _args); fflush(stdout); } while (0)

#define OPRINTF(_num, _args...) do { if (options.debug >= _num || options.output > _num) { \
		fprintf(stdout, "I: "); \
		fprintf(stdout, _args); fflush(stdout); } } while (0)

#define PTRACE(_num) do { if (options.debug >= _num || options.output >= _num) { \
		fprintf(stderr, NAME "[%d]: T: [%s] %12s +%4d : %s()\n", getpid(), _timestamp(), __FILE__, __LINE__, __func__); \
		fflush(stderr); } } while (0)

void
dumpstack(const char *file, const int line, const char *func)
{
	void *buffer[32];
	int nptr;
	char **strings;
	int i;

	if ((nptr = backtrace(buffer, 32)) && (strings = backtrace_symbols(buffer, nptr))) {
		for (i = 0; i < nptr; i++)
			fprintf(stderr, NAME "[%d]: E: [%s] %12s +%4d : %s() : <stack> %s\n", getpid(), _timestamp(), file, line, func, strings[i]);
		fflush(stderr);
	}
}

/** @} */

/** @section Definitions of Globals, Enumerations, Structures
  * @{ */

const char *program = NAME;

typedef enum {
	CommandDefault = 0,
	CommandAnalyze,
	CommandHelp,
	CommandVersion,
	CommandCopying,
} Command;

#define PACANA_ANALYSIS_SHADOW	    (1<<0)
#define PACANA_ANALYSIS_PROVIDES    (1<<1)
#define PACANA_ANALYSIS_ALTERNATE   (1<<2)
#define PACANA_ANALYSIS_OUTDATED    (1<<3)
#define PACANA_ANALYSIS_VCSCHECK    (1<<4)
#define PACANA_ANALYSIS_ALL	    (PACANA_ANALYSIS_SHADOW\
				    |PACANA_ANALYSIS_PROVIDES\
				    |PACANA_ANALYSIS_ALTERNATE\
				    |PACANA_ANALYSIS_OUTDATED\
				    |PACANA_ANALYSIS_VCSCHECK)

typedef struct {
	int debug;
	int output;
	unsigned long analyses;
	Command command;
} Options;

Options options = {
	.debug = 0,
	.output = 1,
	.analyses = PACANA_ANALYSIS_ALL,
	.command = CommandDefault,
};

struct dbhash {
	alpm_db_t *db;
	GHashTable *hash;
};

/** @} */

/** @section Analyze
  * @{ */

static alpm_list_t *
get_database_names(void)
{
	alpm_list_t *list = NULL;
	char buf[81] = { 0, };
	size_t l;
	FILE *f;

	DPRINTF(1, "Opening /etc/pacman.conf\n");
	if ((f = fopen("/etc/pacman.conf", "r"))) {
		while (fgets(buf, 80, f)) {
			if (!(l = strlen(buf)))
				continue;
			l--;
			if (buf[l] == '\n') {
				buf[l] = '\0';
				l--;
			}
			if (!l)
				continue;
			DPRINTF(1, "Got line [%zd]: \"%s\"\n", l, buf);
			if (buf[0] == '[' && buf[l] == ']') {
				buf[l] = '\0';
				if (strcmp(buf + 1, "options")) {
					list = alpm_list_add(list, strdup(buf + 1));
					DPRINTF(1, "Added ALPM database: %s\n", buf + 1);
				}
			}
		}
		fclose(f);
	} else {
		EPRINTF("Could not open /etc/pacman.conf: %s\n", strerror(errno));
	}
	return (list);
}

static void
destroy_dbhash(gpointer data)
{
	struct dbhash *dbhash = data;

	if (dbhash->hash)
		g_hash_table_destroy(dbhash->hash);
	dbhash->db = NULL;
	dbhash->hash = NULL;
	free(dbhash);
}

void
check_shadow(GSList *s, alpm_pkg_t *pkg)
{
	struct dbhash *dbhash = s->data;
	const char *sync = alpm_db_get_name(dbhash->db);
	const char *name = alpm_pkg_get_name(pkg);
	const char *vers = alpm_pkg_get_version(pkg);
	for (GSList *n = s->next; n; n = n->next) {
		struct dbhash *dbhash2 = n->data;
		const char *sync2 = alpm_db_get_name(dbhash2->db);
		if (strstr(sync2, "testing"))
			continue;
		alpm_pkg_t *pkg2;
		if ((pkg2 = alpm_db_get_pkg(dbhash2->db, name))) {
			const char *name2 = alpm_pkg_get_name(pkg2);
			const char *vers2 = alpm_pkg_get_version(pkg2);

			WPRINTF("%s/%s %s masks %s/%s %s\n",
					sync, name, vers, sync2, name2, vers2);
			switch (alpm_pkg_vercmp(vers, vers2)) {
			case -1:
				WPRINTF("%s/%s %s out of date\n", sync, name, vers);
				break;
			case 0:
				break;
			case 1:
				WPRINTF("%s/%s %s out of date\n", sync2, name2, vers2);
				break;
			}
		}
	}
}

gboolean
find_depends(alpm_list_t *d, const char *name)
{
	for (; d; d = alpm_list_next(d)) {
		alpm_depend_t *n = d->data;

		if (!strcmp(n->name, name))
			return TRUE;
	}
	return FALSE;
}

gboolean
vcs_package(alpm_pkg_t *pkg)
{
	char buf[5] = { 0, };
	const char *vcss[] = { "git", "svn", "cvs", "bzr", NULL };
	const char *name = alpm_pkg_get_name(pkg);
	const char **vcs;
	const char *s;
	for (vcs = vcss; *vcs; vcs++) {
		strcpy(buf, "-");
		strcat(buf, *vcs);
		if (!(s = strstr(name, buf)) || s != name + strlen(name) - 4) {
//			alpm_db_t *db = alpm_pkg_get_db(pkg);
//			const char *sync = alpm_db_get_name(db);
//			DPRINTF(1, "%s/%s not named %s\n", sync, name, buf);
			continue;
		}
#if 0
		/* why do binary packages have no makedepends? */
		if (!find_depends(alpm_pkg_get_makedepends(pkg), *vcs)) {
			alpm_db_t *db = alpm_pkg_get_db(pkg);
			const char *sync = alpm_db_get_name(db);
			DPRINTF(1, "%s/%s named %s but no makedepends %s\n", sync, name, buf, *vcs);
			continue;
		}
#endif
		return TRUE;
	}
	return FALSE;
}

void
check_provides(GSList *s, alpm_pkg_t *pkg)
{
	if (vcs_package(pkg))
		return;
	struct dbhash *dbhash = s->data;
	const char *sync = alpm_db_get_name(dbhash->db);
	const char *name = alpm_pkg_get_name(pkg);
	const char *vers = alpm_pkg_get_version(pkg);
	for (alpm_list_t *p = alpm_pkg_get_provides(pkg); p; p = alpm_list_next(p)) {
		alpm_depend_t *d = p->data;
		const char *namep = d->name ? : name;
		const char *versp = d->version;
		if (d->mod == ALPM_DEP_MOD_ANY) {
			versp = vers;
		} else if (d->mod == ALPM_DEP_MOD_EQ) {
			versp = d->version;
		}
		if (!find_depends(alpm_pkg_get_conflicts(pkg), namep))
			continue;
		for (GSList *n = s->next; n; n = n->next) {
			struct dbhash *dbhash2 = n->data;
			alpm_pkg_t *pkg2;
			if ((pkg2 = alpm_db_get_pkg(dbhash2->db, namep))) {
				const char *sync2 = alpm_db_get_name(dbhash2->db);
				const char *name2 = alpm_pkg_get_name(pkg2);
				const char *vers2 = alpm_pkg_get_version(pkg2);

				WPRINTF("%s/%s %s provides %s/%s %s\n",
						sync, name, versp, sync2, name2, vers2);
				if (versp != vers)
					OPRINTF(2, "%s/%s %s provides %s %s\n", sync, name, vers, name2, versp);
				if (versp) {
					switch (alpm_pkg_vercmp(versp, vers2)) {
					case -1:
						if (versp != vers) {
							WPRINTF("%s/%s %s out of date\n", sync, name, vers);
						} else {
							WPRINTF("%s/%s %s could be out of date\n", sync, name, versp);
							OPRINTF(3, "%s/%s %s => add provides=() version to PKGBUILD\n", sync, name, versp);
						}
						break;
					case 0:
						if (versp != vers) {
							OPRINTF(1, "%s/%s %s up to date\n", sync, name, versp);
						} else {
							OPRINTF(1, "%s/%s %s appears up to date\n", sync, name, versp);
							OPRINTF(3, "%s/%s %s => add provides=() version to PKGBUILD\n", sync, name, versp);
						}
						break;
					case 1:
						if (versp != vers) {
							WPRINTF("%s/%s %s out of date\n", sync, name2, vers2);
						} else {
							WPRINTF("%s/%s %s could be out of date\n", sync, name2, vers2);
							OPRINTF(3, "%s/%s %s => add provides=() version to PKGBUILD\n", sync, name, versp);
						}
						break;
					}
				}
			}
		}
	}
}

void
check_vcscheck(GSList *s, alpm_pkg_t *pkg)
{
	if (!vcs_package(pkg))
		return;
	struct dbhash *dbhash = s->data;
	const char *sync = alpm_db_get_name(dbhash->db);
	const char *name = alpm_pkg_get_name(pkg);
	const char *vers = alpm_pkg_get_version(pkg);
	for (alpm_list_t *p = alpm_pkg_get_provides(pkg); p; p = alpm_list_next(p)) {
		alpm_depend_t *d = p->data;
		const char *namep = d->name ? : name;
		const char *versp = d->version;
		if (d->mod == ALPM_DEP_MOD_ANY) {
			versp = vers;
		} else if (d->mod == ALPM_DEP_MOD_EQ) {
			versp = d->version;
		}
		if (!find_depends(alpm_pkg_get_conflicts(pkg), namep))
			continue;
		for (GSList *n = s->next; n; n = n->next) {
			struct dbhash *dbhash2 = n->data;
			alpm_pkg_t *pkg2;
			if ((pkg2 = alpm_db_get_pkg(dbhash2->db, namep))) {
				const char *sync2 = alpm_db_get_name(dbhash2->db);
				const char *name2 = alpm_pkg_get_name(pkg2);
				const char *vers2 = alpm_pkg_get_version(pkg2);

				WPRINTF("%s/%s %s vcs package for %s/%s %s\n",
						sync, name, vers, sync2, name2, vers2);
				if (versp != vers)
					OPRINTF(2, "%s/%s %s provides %s %s\n", sync, name, vers, name2, versp);
				if (versp) {
					switch (alpm_pkg_vercmp(versp, vers2)) {
					case -1:
						if (versp != vers) {
							WPRINTF("%s/%s %s out of date\n", sync, name, versp);
						} else {
							WPRINTF("%s/%s %s could be out of date\n", sync, name, versp);
							OPRINTF(3, "%s/%s %s => add provides=() version to PKGBUILD\n", sync, name, versp);
						}
						break;
					case 0:
						if (versp != vers) {
							OPRINTF(2, "%s/%s %s up to date\n", sync, name, versp);
						} else {
							OPRINTF(2, "%s/%s %s appears up to date\n", sync, name, versp);
							OPRINTF(3, "%s/%s %s => add provides=() version to PKGBUILD\n", sync, name, versp);
						}
						break;
					case 1:
						if (versp != vers) {
							WPRINTF("%s/%s %s out of date\n", sync, name2, vers2);
						} else {
							WPRINTF("%s/%s %s could be out of date\n", sync, name2, vers2);
							OPRINTF(3, "%s/%s %s => add provides=() version to PKGBUILD\n", sync, name, versp);
						}
						break;
					}
				}
			}
		}
	}
}

static void
pac_analyze(void)
{

	const char *version = alpm_version();

	DPRINTF(1, "ALPM version: %s\n", version);

	int caps = alpm_capabilities();

	if (caps & ALPM_CAPABILITY_NLS)
		DPRINTF(1, "ALPM capability NLS\n");
	if (caps & ALPM_CAPABILITY_DOWNLOADER)
		DPRINTF(1, "ALPM capability DOWNLOADER\n");
	if (caps & ALPM_CAPABILITY_SIGNATURES)
		DPRINTF(1, "ALPM capability SIGNATURES\n");

	alpm_errno_t error = 0;
	alpm_handle_t *handle = alpm_initialize("/", "/var/lib/pacman/", &error);

	if (!handle || error != 0) {
		EPRINTF("Could not initialize ALPM: %s\n", alpm_strerror(error));
		exit(EXIT_FAILURE);
	}
	alpm_list_t *list;
	alpm_list_t *d;

	list = get_database_names();
	for (d = list; d; d = alpm_list_next(d)) {
		const char *name = d->data;

		alpm_register_syncdb(handle, name, ALPM_SIG_DATABASE_OPTIONAL);
		DPRINTF(1, "ALPM database: %s\n", name);
	}
	GSList *slist = NULL;
	struct dbhash *dbhash;

	dbhash = calloc(1, sizeof(*dbhash));
	dbhash->db = alpm_get_localdb(handle);
	dbhash->hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	slist = g_slist_append(slist, dbhash);
	{
		size_t count = 0;

		DPRINTF(1, "ALPM database: %s\n", alpm_db_get_name(dbhash->db));
		alpm_list_t *pkgs = alpm_db_get_pkgcache(dbhash->db);
		alpm_list_t *p;

		for (p = pkgs; p; p = alpm_list_next(p)) {
			alpm_pkg_t *pkg = p->data;
			char *name = strdup(alpm_pkg_get_name(pkg));

			DPRINTF(1, "ALPM package: %s/%s\n", alpm_db_get_name(dbhash->db), name);
			g_hash_table_insert(dbhash->hash, name, pkg);
			count++;
		}
		DPRINTF(1, "ALPM database: %s (%zd packages)\n", alpm_db_get_name(dbhash->db), count);
	}
	list = alpm_get_syncdbs(handle);
	for (d = list; d; d = alpm_list_next(d)) {
		dbhash = calloc(1, sizeof(*dbhash));
		dbhash->db = d->data;
		dbhash->hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
		slist = g_slist_append(slist, dbhash);
		{
			size_t count = 0;

			DPRINTF(1, "ALPM database: %s\n", alpm_db_get_name(dbhash->db));
			alpm_list_t *pkgs = alpm_db_get_pkgcache(dbhash->db);
			alpm_list_t *p;

			for (p = pkgs; p; p = alpm_list_next(p)) {
				alpm_pkg_t *pkg = p->data;
				char *name = strdup(alpm_pkg_get_name(pkg));

				DPRINTF(1, "ALPM package: %s/%s\n", alpm_db_get_name(dbhash->db), name);
				g_hash_table_insert(dbhash->hash, name, pkg);
				count++;
			}
			DPRINTF(1, "ALPM database: %s (%zd packages)\n", alpm_db_get_name(dbhash->db), count);
		}
	}

	GSList *s;

	if (options.analyses & PACANA_ANALYSIS_SHADOW) {
		OPRINTF(1, "Performing SHADOW analysis:\n");
		/* skip local database */
		for (s = slist->next; s; s = s->next) {
			dbhash = s->data;
			alpm_list_t *pkgs = alpm_db_get_pkgcache(dbhash->db);
			alpm_list_t *p;

			for (p = pkgs; p; p = alpm_list_next(p)) {
				alpm_pkg_t *pkg = p->data;

				check_shadow(s, pkg);
			}
		}
		OPRINTF(1, "Done\n\n");
	}
	if (options.analyses & PACANA_ANALYSIS_PROVIDES) {
		OPRINTF(1, "Performing PROVIDES analysis:\n");
		/* skip local database */
		for (s = slist->next; s; s = s->next) {
			dbhash = s->data;
			alpm_list_t *pkgs = alpm_db_get_pkgcache(dbhash->db);
			alpm_list_t *p;

			for (p = pkgs; p; p = alpm_list_next(p)) {
				alpm_pkg_t *pkg = p->data;

				check_provides(s, pkg);
			}
		}
		OPRINTF(1, "Done\n\n");
	}
	if (options.analyses & PACANA_ANALYSIS_VCSCHECK) {
		OPRINTF(1, "Performing VCSCHECK analysis:\n");
		/* skip local database */
		for (s = slist->next; s; s = s->next) {
			dbhash = s->data;
			alpm_list_t *pkgs = alpm_db_get_pkgcache(dbhash->db);
			alpm_list_t *p;

			for (p = pkgs; p; p = alpm_list_next(p)) {
				alpm_pkg_t *pkg = p->data;

				check_vcscheck(s, pkg);
			}
		}
		OPRINTF(1, "Done\n\n");
	}
	if (options.analyses & PACANA_ANALYSIS_OUTDATED) {
		OPRINTF(1, "Performing OUTDATED analysis:\n");
		WPRINTF("TODO!\n");
		OPRINTF(1, "Done\n\n");
	}
	if (options.analyses & PACANA_ANALYSIS_ALTERNATE) {
		OPRINTF(1, "Performing ALTERNATE analysis:\n");
		WPRINTF("TODO!\n");
		OPRINTF(1, "Done\n\n");
	}
	/* DO MORE! */

	g_slist_free_full(slist, destroy_dbhash);
	alpm_unregister_all_syncdbs(handle);
}

/** @} */

/** @section Main
  * @{ */

static void
copying(int argc, char *argv[])
{
	(void) argc;
	(void) argv;
	if (!options.output && !options.debug)
		return;
	(void) fprintf(stdout, "\
--------------------------------------------------------------------------------\n\
%1$s\n\
--------------------------------------------------------------------------------\n\
Copyright (c) 2010-2019  Monavacon Limited <http://www.monavacon.com/>\n\
Copyright (c) 2002-2009  OpenSS7 Corporation <http://www.openss7.com/>\n\
Copyright (c) 1997-2001  Brian F. G. Bidulock <bidulock@openss7.org>\n\
\n\
All Rights Reserved.\n\
--------------------------------------------------------------------------------\n\
This program is free software: you can  redistribute it  and/or modify  it under\n\
the terms of the  GNU Affero  General  Public  License  as published by the Free\n\
Software Foundation, version 3 of the license.\n\
\n\
This program is distributed in the hope that it will  be useful, but WITHOUT ANY\n\
WARRANTY; without even  the implied warranty of MERCHANTABILITY or FITNESS FOR A\n\
PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.\n\
\n\
You should have received a copy of the  GNU Affero General Public License  along\n\
with this program.   If not, see <http://www.gnu.org/licenses/>, or write to the\n\
Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\
--------------------------------------------------------------------------------\n\
U.S. GOVERNMENT RESTRICTED RIGHTS.  If you are licensing this Software on behalf\n\
of the U.S. Government (\"Government\"), the following provisions apply to you. If\n\
the Software is supplied by the Department of Defense (\"DoD\"), it is classified\n\
as \"Commercial  Computer  Software\"  under  paragraph  252.227-7014  of the  DoD\n\
Supplement  to the  Federal Acquisition Regulations  (\"DFARS\") (or any successor\n\
regulations) and the  Government  is acquiring  only the  license rights granted\n\
herein (the license rights customarily provided to non-Government users). If the\n\
Software is supplied to any unit or agency of the Government  other than DoD, it\n\
is  classified as  \"Restricted Computer Software\" and the Government's rights in\n\
the Software  are defined  in  paragraph 52.227-19  of the  Federal  Acquisition\n\
Regulations (\"FAR\")  (or any successor regulations) or, in the cases of NASA, in\n\
paragraph  18.52.227-86 of  the  NASA  Supplement  to the FAR (or any  successor\n\
regulations).\n\
--------------------------------------------------------------------------------\n\
", NAME " " VERSION);
}

static void
version(int argc, char *argv[])
{
	(void) argc;
	(void) argv;
	if (!options.output && !options.debug)
		return;
	(void) fprintf(stdout, "\
%1$s (OpenSS7 %2$s) %3$s\n\
Written by Brian Bidulock.\n\
\n\
Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019  Monavacon Limited.\n\
Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  OpenSS7 Corporation.\n\
Copyright (c) 1997, 1998, 1999, 2000, 2001  Brian F. G. Bidulock.\n\
This is free software; see the source for copying conditions.  There is NO\n\
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
\n\
Distributed by OpenSS7 under GNU Affero General Public License Version 3,\n\
with conditions, incorporated herein by reference.\n\
\n\
See `%1$s --copying' for copying permissions.\n\
", NAME, PACKAGE, VERSION);
}

static void
usage(int argc, char *argv[])
{
	(void) argc;
	if (!options.output && !options.debug)
		return;
	(void) fprintf(stderr, "\
Usage:\n\
    %1$s [-A|--analyze] [options]\n\
    %1$s {-h|--help} [options]\n\
    %1$s {-V|--version}\n\
    %1$s {-C|--copying}\n\
", argv[0]);
}

const char *
show_analyses(unsigned long analyses)
{
	static char buf[80];

	if (analyses == PACANA_ANALYSIS_ALL)
		return ("all");
	*buf = '\0';
	if (analyses & PACANA_ANALYSIS_SHADOW) {
		if (*buf)
			strcat(buf, ",");
		strcat(buf, "shadow");
	}
	if (analyses & PACANA_ANALYSIS_PROVIDES) {
		if (*buf)
			strcat(buf, ",");
		strcat(buf, "provides");
	}
	if (analyses & PACANA_ANALYSIS_ALTERNATE) {
		if (*buf)
			strcat(buf, ",");
		strcat(buf, "alternate");
	}
	if (analyses & PACANA_ANALYSIS_OUTDATED) {
		if (*buf)
			strcat(buf, ",");
		strcat(buf, "outdated");
	}
	if (analyses & PACANA_ANALYSIS_VCSCHECK) {
		if (*buf)
			strcat(buf, ",");
		strcat(buf, "vcscheck");
	}
	return(buf);
}

static void
help(int argc, char *argv[])
{
	(void) argc;
	if (!options.output && !options.debug)
		return;
	/* *INDENT-OFF* */
	(void) fprintf(stdout, "\
Usage:\n\
    %1$s [-A|--analyze] [options]\n\
    %1$s {-h|--help} [options]\n\
    %1$s {-V|--version}\n\
    %1$s {-C|--copying}\n\
Options:\n\
  Command Options:\n\
   [-A, --analyze]\n\
        analyze pacman sync and local databases\n\
    -h, --help, -?, --?\n\
        print this usage information and exit\n\
    -V, --version\n\
        print version and exit\n\
    -C, --copying\n\
        print copying permission and exit\n\
  Analysis Options:\n\
    -w, --which WHICH[,[!]WHICH]...\n\
        specify which analyses to perform [default: %4$s]\n\
  General Options:\n\
    -D, --debug [LEVEL]\n\
        increment or set debug LEVEL [default: '%2$d']\n\
    -v, --verbose [LEVEL]\n\
        increment or set output verbosity LEVEL [default: '%3$d']\n\
        this option may be repeated.\n\
", argv[0]
	, options.debug
	, options.output
	, show_analyses(options.analyses)
	);
	/* *INDENT-ON* */
}

static void
set_defaults(int argc, char *argv[])
{
	(void) argc;
	(void) argv;
}

static void
get_defaults(int argc, char *argv[])
{
	(void) argc;
	(void) argv;
}

int
main(int argc, char *argv[]) {
	Command command = CommandDefault;

	setlocale(LC_ALL, "");

	set_defaults(argc, argv);

	while (1) {
		int c, val;
		char *endptr = NULL, *str, *p;

#ifdef _GNU_SOURCE
		int option_index = 0;
		/* *INDENT-OFF* */
		static struct option long_options[] = {
			{"analyze",	no_argument,		NULL, 'A'},
			{"which",	required_argument,	NULL, 'w'},

			{"debug",	optional_argument,	NULL, 'D'},
			{"verbose",	optional_argument,	NULL, 'v'},
			{"help",	no_argument,		NULL, 'h'},
			{"version",	no_argument,		NULL, 'V'},
			{"copying",	no_argument,		NULL, 'C'},
			{"?",		no_argument,		NULL, 'H'},
			{ 0, }
		};
		/* *INDENT-ON* */

		c = getopt_long_only(argc, argv, "Aw:D::v::hVCH?", long_options,
				&option_index);
#else				/* defined _GNU_SOURCE */
		c = getopt(argc, argv, "AwDvhVC?");
#endif				/* defined _GNU_SOURCE */
		if (c == -1) {
			if (options.debug)
				fprintf(stderr, "%s: done options processing\n", argv[0]);
			break;
		}
		switch (c) {
		case 0:
			goto bad_usage;
		case 'A':	/* -A, --analyze */
			if (options.command != CommandDefault)
				goto bad_command;
			if (command == CommandDefault)
				command = CommandAnalyze;
			options.command = CommandAnalyze;
			break;
		case 'w':	/* -w, --which [!]WHICH,[[!]WHICH]... */
			options.analyses = 0;
			endptr = NULL;
			for (str = optarg; (p = strtok_r(str, ",", &endptr)); str = NULL) {
				int reverse = 0;

				if (options.debug)
					fprintf(stderr, "%s: got token '%s'\n", argv[0], p);
				if (*p == '!') {
					reverse = 1;
					p++;
				}
				if (*p == '\0')
					continue;
				if (!strcasecmp(p, "all")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_ALL;
					} else {
						options.analyses |= PACANA_ANALYSIS_ALL;
					}
					continue;
				}
				if (!strcasecmp(p, "shadow")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_SHADOW;
					} else {
						options.analyses |= PACANA_ANALYSIS_SHADOW;
					}
					continue;
				}
				if (!strcasecmp(p, "provides")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_PROVIDES;
					} else {
						options.analyses |= PACANA_ANALYSIS_PROVIDES;
					}
					continue;
				}
				if (!strcasecmp(p, "alternate")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_ALTERNATE;
					} else {
						options.analyses |= PACANA_ANALYSIS_ALTERNATE;
					}
					continue;
				}
				if (!strcasecmp(p, "outdated")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_OUTDATED;
					} else {
						options.analyses |= PACANA_ANALYSIS_OUTDATED;
					}
					continue;
				}
				if (!strcasecmp(p, "vcscheck")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_VCSCHECK;
					} else {
						options.analyses |= PACANA_ANALYSIS_VCSCHECK;
					}
					continue;
				}
				goto bad_option;
			}
			if (options.debug)
				fprintf(stderr, "%s: analyses specified(0x%lx): %s\n", argv[0], options.analyses, show_analyses(options.analyses));
			break;
		case 'D':	/* -D, --debug [level] */
			if (options.debug)
				fprintf(stderr, "%s: increasing debug verbosity\n", argv[0]);
			if (optarg == NULL) {
				options.debug++;
				break;
			}
			val = strtoul(optarg, &endptr, 0);
			if (*endptr)
				goto bad_option;
			options.debug = val;
			break;
		case 'v':	/* -v, --verbose [level] */
			if (options.debug)
				fprintf(stderr, "%s: increasing output verbosity\n", argv[0]);
			if (optarg == NULL) {
				options.output++;
				break;
			}
			val = strtoul(optarg, &endptr, 0);
			if (*endptr)
				goto bad_option;
			options.output = val;
			break;
		case 'h':	/* -h, --help */
		case 'H':	/* -H, --? */
			command = CommandHelp;
			break;
		case 'V':	/* -V, --version */
			command = CommandVersion;
			break;
		case 'C':	/* -C, --copying */
			command = CommandCopying;
			break;
		case '?':
		default:
		      bad_option:
			optind--;
		      bad_nonopt:
			if (options.output || options.debug) {
				if (optind < argc) {
					fprintf(stderr, "%s: syntax error near '", argv[0]);
					while (optind < argc)
						fprintf(stderr, "%s ", argv[optind++]);
					fprintf(stderr, "'\n");
				} else {
					fprintf(stderr, "%s: missing option or argument", argv[0]);
					fprintf(stderr, "\n");
				}
				fflush(stderr);
			      bad_usage:
				usage(argc, argv);
			}
			exit(2);
		      bad_command:
			fprintf(stderr, "%s: only one command option allowed\n", argv[0]);
			goto bad_usage;
		}
	}
	if (options.debug) {
		fprintf(stderr, "%s: option index = %d\n", argv[0], optind);
		fprintf(stderr, "%s: option count = %d\n", argv[0], argc);
	}
	if (optind < argc)
		goto bad_nonopt;

	get_defaults(argc, argv);

	switch (command) {
	case CommandHelp:
		if (options.debug)
			fprintf(stderr, "%s: printing help message\n", argv[0]);
		help(argc, argv);
		exit(EXIT_SUCCESS);
	case CommandVersion:
		if (options.debug)
			fprintf(stderr, "%s: printing version message\n", argv[0]);
		version(argc, argv);
		exit(EXIT_SUCCESS);
	case CommandCopying:
		if (options.debug)
			fprintf(stderr, "%s: printing copying message\n", argv[0]);
		copying(argc, argv);
		exit(EXIT_SUCCESS);
	case CommandDefault:
		options.command = command = CommandAnalyze;
		/* fall thru */
	case CommandAnalyze:
		pac_analyze();
		exit(EXIT_SUCCESS);
	}
	EPRINTF("invalid command\n");
	exit(EXIT_FAILURE);
}

/** @} */

// vim: set sw=8 tw=80 com=srO\:/**,mb\:*,ex\:*/,srO\:/*,mb\:*,ex\:*/,b\:TRANS foldmarker=@{,@} foldmethod=marker:
