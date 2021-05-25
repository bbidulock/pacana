/*****************************************************************************

 Copyright (c) 2010-2021  Monavacon Limited <http://www.monavacon.com/>
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

#include <curl/curl.h>
#include <json-c/json.h>

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
#define PACANA_ANALYSIS_STRANDED    (1<<5)
#define PACANA_ANALYSIS_AURCHECK    (1<<6)
#define PACANA_ANALYSIS_MISSING     (1<<7)
#define PACANA_ANALYSIS_ALL	    (PACANA_ANALYSIS_SHADOW\
				    |PACANA_ANALYSIS_PROVIDES\
				    |PACANA_ANALYSIS_ALTERNATE\
				    |PACANA_ANALYSIS_OUTDATED\
				    |PACANA_ANALYSIS_VCSCHECK\
				    |PACANA_ANALYSIS_STRANDED\
				    |PACANA_ANALYSIS_AURCHECK\
				    |PACANA_ANALYSIS_MISSING)
#define AUR_DEFAULT_URL		    "https://aur.archlinux.org/rpc/"
#define ARCH_STANDARD_REPOS	    "core,extra,community,multilib,ec2,testing,community-testing,multilib-testing"
#define AUR_MAXLEN		    4443

typedef struct {
	int debug;
	int output;
	unsigned long analyses;
	Command command;
	char *url;
	char *repos;
	char *custom;
	int dryrun;
} Options;

Options options = {
	.debug = 0,
	.output = 1,
	.analyses = PACANA_ANALYSIS_ALL,
	.command = CommandDefault,
	.url = NULL,
	.repos = NULL,
	.custom = NULL,
	.dryrun = 0,
};

struct dbhash {
	alpm_db_t *db;
	char *name;
	alpm_list_t *pkgs;
	GHashTable *hash;
	gboolean custom;
};

/** @} */

/** @section Analyze
  * @{ */

int in_list(const char *list, const char *name)
{
	char *where;
	int len;

	if (!list || !list[0] || !name)
		return (0);
	len = strlen(name);
	if ((where = strstr(list, name))) {
		if ((where == list || where[-1] == ',' || where[-1] == '!') && (where[len] == '\0' || where[len] == ',')) {
			if (where != list && where[-1] == '!')
				return (-1);
			return (1);
		}
	}
	return (0);
}

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
	free(dbhash->name);
	dbhash->name = NULL;
	dbhash->pkgs = NULL;
	dbhash->hash = NULL;
	free(dbhash);
}

typedef struct aur_pkg {
	char *base;			/* like alpm_pkg_get_base */
	char *name;			/* like alpm_pkg_get_name */
	char *version;			/* like alpm_pkg_get_version */
	char *desc;			/* like alpm_pkg_get_desc */
	char *url;			/* like alpm_pkg_get_url */
	alpm_list_t *licenses;		/* like alpm_pkg_get_licenses */
	alpm_list_t *groups;		/* like alpm_pkg_get_groups */
	alpm_list_t *depends;		/* like alpm_pkg_get_depends */
	alpm_list_t *optdepends;	/* like alpm_pkg_get_optdepends */
	alpm_list_t *checkdepends;	/* like alpm_pkg_get_checkdepends */
	alpm_list_t *makedepends;	/* like alpm_pkg_get_makedepends */
	alpm_list_t *conflicts;		/* like alpm_pkg_get_conflicts */
	alpm_list_t *provides;		/* like alpm_pkg_get_provides */
	alpm_list_t *replaces;		/* like alpm_pkg_get_replaces */
	char *maintainer;
#if 0
	int id;
	int baseid;
	int numvotes;
	double popularity;
	char *maintainer;
	time_t first_submitted;
	time_t last_modified;
	char *urlpath;
	alpm_list_t *keywords;
#endif
} aur_pkg_t;

const char *
aur_pkg_get_base(aur_pkg_t *pkg)
{
	return (pkg->base);
}

const char *
aur_pkg_get_name(aur_pkg_t *pkg)
{
	return (pkg->name);
}

const char *
aur_pkg_get_version(aur_pkg_t *pkg)
{
	return (pkg->version);
}

const char *
aur_pkg_get_desc(aur_pkg_t *pkg)
{
	return (pkg->desc);
}

const char *
aur_pkg_get_url(aur_pkg_t *pkg)
{
	return (pkg->url);
}

alpm_list_t *
aur_pkg_get_licenses(aur_pkg_t *pkg)
{
	return (pkg->licenses);
}


alpm_list_t *
aur_pkg_get_groups(aur_pkg_t *pkg)
{
	return (pkg->groups);
}


alpm_list_t *
aur_pkg_get_depends(aur_pkg_t *pkg)
{
	return (pkg->depends);
}


alpm_list_t *
aur_pkg_get_optdepends(aur_pkg_t *pkg)
{
	return (pkg->optdepends);
}


alpm_list_t *
aur_pkg_get_checkdepends(aur_pkg_t *pkg)
{
	return (pkg->checkdepends);
}


alpm_list_t *
aur_pkg_get_makedepends(aur_pkg_t *pkg)
{
	return (pkg->makedepends);
}


alpm_list_t *
aur_pkg_get_conflicts(aur_pkg_t *pkg)
{
	return (pkg->conflicts);
}


alpm_list_t *
aur_pkg_get_provides(aur_pkg_t *pkg)
{
	return (pkg->provides);
}


alpm_list_t *
aur_pkg_get_replaces(aur_pkg_t *pkg)
{
	return (pkg->replaces);
}

struct dbhash *aur_db = NULL;
GHashTable *provided = NULL;

void
check_shadow(GSList *s, alpm_pkg_t *pkg)
{
	struct dbhash *dbhash = s->data;
	const char *sync = dbhash->name;
	const char *name = alpm_pkg_get_name(pkg);
	const char *vers = alpm_pkg_get_version(pkg);
	for (GSList *n = s->next; n; n = n->next) {
		struct dbhash *dbhash2 = n->data;
		const char *sync2 = dbhash2->name;
		if (strstr(sync2, "testing"))
			continue;
		alpm_pkg_t *pkg2;
		if ((pkg2 = g_hash_table_lookup(dbhash2->hash, name))) {
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
	const char *sync = dbhash->name;
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
			if ((pkg2 = g_hash_table_lookup(dbhash2->hash, namep))) {
				const char *sync2 = dbhash2->name;
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
							WPRINTF("%s/%s %s out of date\n", sync2, name2, vers2);
						} else {
							WPRINTF("%s/%s %s could be out of date\n", sync2, name2, vers2);
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
	const char *sync = dbhash->name;
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
			if ((pkg2 = g_hash_table_lookup(dbhash2->hash, namep))) {
				const char *sync2 = dbhash2->name;
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
							WPRINTF("%s/%s %s out of date\n", sync2, name2, vers2);
						} else {
							WPRINTF("%s/%s %s could be out of date\n", sync2, name2, vers2);
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
check_stranded_local(GSList *slist, alpm_pkg_t *pkg)
{
	struct dbhash *dbhash = slist->data;
	const char *sync = dbhash->name;
	const char *name = alpm_pkg_get_name(pkg);
	const char *vers = alpm_pkg_get_version(pkg);
	int found = 0;
	GSList *s;

	/* skip local database */
	for (s = slist->next; s; s = s->next) {
		dbhash = s->data;
		if (g_hash_table_lookup(dbhash->hash, name)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		/* Package from local database not found in any other sync database. This 
		   package, by definition is foreign.  Without checking the AUR, this
		   package will be marked foreign.  When we can check the AUR and it
		   exists in the AUR, this package is marked stranded.  When it does not
		   exist in the AUR, it is marked as foreign. */
		/* If the package exists in the AUR and the AUR package version is newer
		   than that of the package, mark it as out of date. */

		aur_pkg_t *pkg2;
		struct dbhash *dbhash2 = aur_db;

		if ((pkg2 = g_hash_table_lookup(dbhash2->hash, name))) {
			const char *sync2 = dbhash2->name;
			const char *name2 = aur_pkg_get_base(pkg2);
			const char *vers2 = aur_pkg_get_version(pkg2);

			WPRINTF("%s/%s %s divorced to %s/%s %s\n", sync, name, vers, sync2, name2, vers2);

			switch (alpm_pkg_vercmp(vers, vers2)) {
			case -1:
				WPRINTF("%s/%s %s out of date\n", sync, name, vers);
				OPRINTF(3, "%s/%s %s => rebuild from %s/%s %s\n", sync, name, vers, sync2, name2, vers2);
				break;
			case 0:
				break;
			case 1:
				if (!vcs_package(pkg))
					WPRINTF("%s/%s %s out of date\n", sync2, name2, vers2);
				break;
			}
			if (!pkg2->maintainer) {
				WPRINTF("%s/%s %s is an orphan\n", sync2, name2, vers2);
				OPRINTF(3, "%s/%s %s => adopt package\n", sync2, name2, vers2);
			}
		} else {
			WPRINTF("%s/%s %s foreign\n", sync, name, vers);
		}
	}
}

void
check_stranded_custom(GSList *s, alpm_pkg_t *pkg)
{
	if (!options.url)
		return;

	struct dbhash *dbhash = s->data;
	const char *sync = dbhash->name;
	const char *name = alpm_pkg_get_name(pkg);
	const char *vers = alpm_pkg_get_version(pkg);

	aur_pkg_t *pkg2;
	struct dbhash *dbhash2 = aur_db;

	if ((pkg2 = g_hash_table_lookup(dbhash2->hash, name))) {
		const char *sync2 = dbhash2->name;
		const char *name2 = aur_pkg_get_base(pkg2);
		const char *vers2 = aur_pkg_get_version(pkg2);

		switch (alpm_pkg_vercmp(vers, vers2)) {
		case -1:
			WPRINTF("%s/%s %s built from %s/%s %s\n", sync, name, vers, sync2, name2, vers2);
			WPRINTF("%s/%s %s out of date\n", sync, name, vers);
			OPRINTF(3, "%s/%s %s => rebuild from %s/%s %s\n", sync, name, vers, sync2, name2, vers2);
			break;
		case 0:
			OPRINTF(2, "%s/%s %s built from %s/%s %s\n", sync, name, vers, sync2, name2, vers2);
			break;
		case 1:
			WPRINTF("%s/%s %s built from %s/%s %s\n", sync, name, vers, sync2, name2, vers2);
			if (!vcs_package(pkg))
				WPRINTF("%s/%s %s out of date\n", sync2, name2, vers2);
			break;
		}

		if (!pkg2->maintainer) {
			WPRINTF("%s/%s %s is an orphan\n", sync2, name2, vers2);
			OPRINTF(3, "%s/%s %s => adopt package\n", sync2, name2, vers2);
		}
	} else {
		WPRINTF("%s/%s %s stranded\n", sync, name, vers);
	}
}

void
check_missing(GSList *s, alpm_pkg_t *pkg)
{
	struct dbhash *dbhash = s->data;
	const char *sync = dbhash->name;
	const char *name = alpm_pkg_get_name(pkg);
	const char *vers = alpm_pkg_get_version(pkg);

	alpm_list_t *d;

	for (d = alpm_pkg_get_depends(pkg); d; d = alpm_list_next(d)) {
		alpm_depend_t *dep = d->data;

		const char *dname = dep->name;

		if (!g_hash_table_contains(provided, dname)) {
			if (options.url) {
				aur_pkg_t *pkg2;
				struct dbhash *dbhash2 = aur_db;

				if ((pkg2 = g_hash_table_lookup(dbhash2->hash, dname))) {
					const char *sync2 = dbhash2->name;
					const char *name2 = aur_pkg_get_base(pkg2);
					const char *vers2 = aur_pkg_get_version(pkg2);

					WPRINTF("%s/%s %s dependency %s needs: %s/%s %s\n", sync, name, vers, dname, sync2, name2, vers2);
					OPRINTF(3, "%s/%s %s => build %s from %s/%s %s\n", sync, name, vers, dname, sync2, name2, vers2);
					if (!pkg2->maintainer) {
						WPRINTF("%s/%s %s is an orphan\n", sync2, name2, vers2);
						OPRINTF(3, "%s/%s %s => adopt package\n", sync2, name2, vers2);
					}
				} else {
					WPRINTF("%s/%s %s dependency missing: %s\n", sync, name, vers, dname);
					OPRINTF(3, "%s/%s %s => create package for %s\n", sync, name, vers, dname);
				}
			} else {
				WPRINTF("%s/%s %s dependency missing: %s\n", sync, name, vers, dname);
				OPRINTF(3, "%s/%s %s => find package for %s\n", sync, name, vers, dname);
			}
		}
	}

}

void
freeit(gpointer data)
{
	free(data);
}

int
parse_data(const char *data)
{
	struct json_object *info, *obj, *results, *pkg;
	enum json_tokener_error err = 0;
	size_t i, length;
	struct dbhash *dbhash;

	info = json_tokener_parse_verbose(data, &err);
	if (!info) {
		EPRINTF("Could not parse data: %s\n", json_tokener_error_desc(err));
		return (-1);
	}
	if (!json_object_is_type(info, json_type_object)) {
		EPRINTF("Result wrong object type.\n");
		goto reject;
	}
	if (!(obj = json_object_object_get(info, "version")) || json_object_get_int(obj) != 5) {
		EPRINTF("Result has wrong version.\n");
		goto reject;
	}
	if (!(obj = json_object_object_get(info, "type")) || strcmp(json_object_get_string(obj), "multiinfo")) {
		EPRINTF("Result has wrong type.\n");
		goto reject;
	}
	if (!(obj = json_object_object_get(info, "resultcount"))) {
		EPRINTF("Result has no resultcount.\n");
		goto reject;
	}
	if (!json_object_get_int(obj)) {
		goto done;
	}
	if (!(results = json_object_object_get(info, "results")) || !json_object_is_type(results, json_type_array)) {
		EPRINTF("Result has no results.\n");
		goto reject;
	}
	if (!(length = json_object_array_length(results))) {
		goto done;
	}
	if (!(dbhash = aur_db)) {
		dbhash = calloc(1, sizeof(*aur_db));
		dbhash->name = strdup("aur");
		dbhash->pkgs = NULL;
		dbhash->hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
		aur_db = dbhash;
	}
	for (i = 0; i < length; i++) {
		aur_pkg_t *aur_pkg;
		const char *str;
		struct json_object *array;

		if (!(pkg = json_object_array_get_idx(results, i)) || !json_object_is_type(pkg, json_type_object)) {
			EPRINTF("Wrong object type.\n");
			continue;
		}
		if (!(obj = json_object_object_get(pkg, "Name")) || !(str = json_object_get_string(obj))) {
			EPRINTF("AUR Package has no name.\n");
			continue;
		}
		aur_pkg = calloc(1, sizeof(*aur_pkg));
		alpm_list_append(&dbhash->pkgs, aur_pkg);
		aur_pkg->name = strdup(str);
		g_hash_table_insert(dbhash->hash, strdup(aur_pkg->name), aur_pkg);
		DPRINTF(1, "AUR package: %s/%s\n", dbhash->name, aur_pkg->name);
		if (!g_hash_table_lookup(dbhash->hash, aur_pkg->name))
			EPRINTF("Can't look up %s/%s\n", dbhash->name, aur_pkg->name);
		if ((obj = json_object_object_get(pkg, "PackageBase")) && (str = json_object_get_string(obj)))
			aur_pkg->base = strdup(str);
		if ((obj = json_object_object_get(pkg, "Version")) && (str = json_object_get_string(obj)))
			aur_pkg->version = strdup(str);
		if ((obj = json_object_object_get(pkg, "Description")) && (str = json_object_get_string(obj)))
			aur_pkg->desc = strdup(str);
		if ((obj = json_object_object_get(pkg, "URL")) && (str = json_object_get_string(obj)))
			aur_pkg->url = strdup(str);
		if ((array = json_object_object_get(pkg, "License"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append_strdup(&aur_pkg->licenses, json_object_get_string(obj));
		}
		if ((array = json_object_object_get(pkg, "Groups")) && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append_strdup(&aur_pkg->groups, json_object_get_string(obj));
		}
		if ((array = json_object_object_get(pkg, "Depends"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append(&aur_pkg->depends,
							 alpm_dep_from_string(json_object_get_string(obj)));
		}
		if ((array = json_object_object_get(pkg, "OptDepends"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append(&aur_pkg->optdepends,
							 alpm_dep_from_string(json_object_get_string(obj)));
		}
		if ((array = json_object_object_get(pkg, "CheckDepends"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append(&aur_pkg->checkdepends,
							 alpm_dep_from_string(json_object_get_string(obj)));
		}
		if ((array = json_object_object_get(pkg, "MakeDepends"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append(&aur_pkg->makedepends,
							 alpm_dep_from_string(json_object_get_string(obj)));
		}
		if ((array = json_object_object_get(pkg, "Conflicts"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append(&aur_pkg->conflicts,
							 alpm_dep_from_string(json_object_get_string(obj)));
		}
		if ((array = json_object_object_get(pkg, "Provides"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append(&aur_pkg->provides,
							 alpm_dep_from_string(json_object_get_string(obj)));
		}
		if ((array = json_object_object_get(pkg, "Replaces"))
		    && json_object_is_type(array, json_type_array)) {
			size_t n, number;

			number = json_object_array_length(array);
			for (n = 0; n < number; n++)
				if ((obj = json_object_array_get_idx(array, n))
				    && json_object_is_type(obj, json_type_string))
					alpm_list_append(&aur_pkg->replaces,
							 alpm_dep_from_string(json_object_get_string(obj)));
		}
		if ((obj = json_object_object_get(pkg, "Maintainer"))
				&& json_object_is_type(obj, json_type_string)
				&& (str = json_object_get_string(obj))) {
			aur_pkg->maintainer = strdup(str);
		}
	}
      done:
	json_object_put(info);
	return (0);
      reject:
	json_object_put(info);
	return (-1);
}

size_t
writedata_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	GStrvBuilder *svb = userdata;
	gchar *data;

	(void) size;
	if ((data = g_strndup(ptr, nmemb))) {
		g_strv_builder_add(svb, data);
		return (nmemb);
	}
	return (0);
}

int
aur_lookup_info(const char *uri)
{
	CURL *curl;

	/* lookup info using CURL and parse result with JSON */
	if (options.dryrun) {
		OPRINTF(1, "Would look up:\n%s\n", uri);
		return (0);
	}
	if (!(curl = curl_easy_init())) {
		EPRINTF("Could not get CURL easy handle.\n");
		return (-1);
	}
	curl_easy_setopt(curl, CURLOPT_URL, uri);
	GStrvBuilder *svb = g_strv_builder_new();

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, svb);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writedata_callback);
	DPRINTF(1, "Lookup up in AUR:\n%s\n", uri);
	CURLcode res = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	if (res != CURLE_OK) {
		EPRINTF("CURL error: %s\n", curl_easy_strerror(res));
		return (-1);
	}
	GStrv strv = g_strv_builder_end(svb);

	g_strv_builder_unref(svb);
	if (!strv) {
		return (-1);
	}
	gchar *data = g_strjoinv(NULL, strv);

	g_strfreev(strv);
	if (!data) {
		return (-1);
	}

	DPRINTF(1, "Got AUR info:\n%s\n", data);
	int err = parse_data(data);

	g_free(data);
	return (err);
}

int
aur_lookup(GSList *alist)
{
	GSList *a;
	static char buf[AUR_MAXLEN + 1] = { 0, };
	int urllen, err;

	for (a = alist; a; a = a->next) {
		strcpy(buf, options.url);
		strcat(buf, "?v=5&type=info");
		urllen = strlen(buf);
		for (; a; a = a->next) {
			int len = strlen(a->data);

			if (urllen + 7 + len > AUR_MAXLEN)
				break;
			strcat(buf, "&arg[]=");
			strcat(buf, a->data);
			urllen += 7 + len;
		}
		if ((err = aur_lookup_info(buf)))
			return (err);
		if (!a)
			break;
	}
	return (0);
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
	provided = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	GSList *slist = NULL;
	struct dbhash *dbhash;
	alpm_db_t *db;


	dbhash = calloc(1, sizeof(*dbhash));
	db = alpm_get_localdb(handle);
	dbhash->name = strdup(alpm_db_get_name(db));
	dbhash->pkgs = alpm_db_get_pkgcache(db);
	dbhash->hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	slist = g_slist_append(slist, dbhash);
	{
		size_t count = 0;

		DPRINTF(1, "ALPM database: %s\n", dbhash->name);
		alpm_list_t *p;

		for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
			alpm_pkg_t *pkg = p->data;
			const char *name = alpm_pkg_get_name(pkg);

			DPRINTF(1, "ALPM package: %s/%s\n", dbhash->name, name);
			g_hash_table_insert(dbhash->hash, strdup(name), pkg);
			count++;

			g_hash_table_add(provided, strdup(name));
			alpm_list_t *d;
			for (d = alpm_pkg_get_provides(pkg); d; d = alpm_list_next(d)) {
				alpm_depend_t *dep = d->data;
				g_hash_table_add(provided, strdup(dep->name));
			}
		}
		DPRINTF(1, "ALPM database: %s (%zd packages)\n", dbhash->name, count);
	}
	list = alpm_get_syncdbs(handle);
	for (d = list; d; d = alpm_list_next(d)) {
		dbhash = calloc(1, sizeof(*dbhash));
		db = d->data;
		dbhash->name = strdup(alpm_db_get_name(db));
		dbhash->pkgs = alpm_db_get_pkgcache(db);
		dbhash->hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
		slist = g_slist_append(slist, dbhash);
		{
			size_t count = 0;

			DPRINTF(1, "ALPM database: %s\n", dbhash->name);
			alpm_list_t *p;

			for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
				alpm_pkg_t *pkg = p->data;
				const char *name = alpm_pkg_get_name(pkg);

				DPRINTF(1, "ALPM package: %s/%s\n", dbhash->name, name);
				g_hash_table_insert(dbhash->hash, strdup(name), pkg);
				count++;

				g_hash_table_add(provided, strdup(name));
				alpm_list_t *d;
				for (d = alpm_pkg_get_provides(pkg); d; d = alpm_list_next(d)) {
					alpm_depend_t *dep = d->data;
					g_hash_table_add(provided, strdup(dep->name));
				}
			}
			DPRINTF(1, "ALPM database: %s (%zd packages)\n", dbhash->name, count);
		}
	}

	GSList *s;

	/* 
	 * When the AUR is activated we need a list of all packages that exist
	 * in the local database that do not exist in any sync database and the
	 * list of all packages that exist in a "custom" sync database, and then
	 * obtain information about them from the AUR.
	 */
	if (options.url) {
		GSList *alist = NULL;

		dbhash = slist->data;
		alpm_list_t *p;

		/* First, add to the list the names of all packages that exist in the
		   local database that do not exist in any sync database. */
		for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
			alpm_pkg_t *pkg = p->data;
			const char *name = alpm_pkg_get_name(pkg);
			int found = 0;

			/* skip local database */
			for (s = slist->next; s; s = s->next) {
				dbhash = s->data;
				if (g_hash_table_lookup(dbhash->hash, name)) {
					found = 1;
					break;
				}
			}
			if (!found) {
				DPRINTF(1, "Adding to AUR list: %s\n", name);
				alist = g_slist_append(alist, strdup(name));
			}
		}
		/* Second, get a list of sync databases that are considered "custom".  */
		/* skip local database */
		for (s = slist->next; s; s = s->next) {
			dbhash = s->data;
			const char *sync = dbhash->name;

			if (options.custom) {
				switch (in_list(options.custom, sync)) {
				case -1:	/* in list with ! prefixed */
					dbhash->custom = FALSE;
					continue;
				case 0:	/* not in list */
					dbhash->custom = FALSE;
					continue;
				case 1:	/* in list without ! prefixed */
					dbhash->custom = TRUE;
					break;
				}
			} else {
				switch (in_list(ARCH_STANDARD_REPOS, sync)) {
				case -1:	/* in list with ! prefixed */
					dbhash->custom = TRUE;
					break;
				case 0:	/* not in list */
					dbhash->custom = TRUE;
					break;
				case 1:	/* in list without ! prefixed */
					dbhash->custom = FALSE;
					continue;
				}
			}
			DPRINTF(1, "Adding to AUR list: --> packages from %s <--\n", sync);
			/* Third, add to the list the names of all packages from the
			   custom databases. */
			alpm_list_t *p;

			for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
				alpm_pkg_t *pkg = p->data;
				const char *name = alpm_pkg_get_name(pkg);

				DPRINTF(1, "Adding to AUR list: %s\n", name);
				alist = g_slist_append(alist, strdup(name));
			}
		}
		if (options.analyses & PACANA_ANALYSIS_MISSING) {
			/* Find all the missing dependencies (those in no sync
			   database) and add them to the AUR list. */
			for (s = slist; s; s = s->next) {
				dbhash = s->data;
				alpm_list_t *p;
				for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
					alpm_pkg_t *pkg = p->data;

					alpm_list_t *d;
					for (d = alpm_pkg_get_depends(pkg); d; d = alpm_list_next(d)) {
						alpm_depend_t *dep = d->data;
						const char *name = dep->name;

						if (!g_hash_table_contains(provided, name)) {
							DPRINTF(1, "Adding to AUR list: %s\n", name);
							alist = g_slist_append(alist, strdup(name));
						}
					}
				}
			}
		}
		if (aur_lookup(alist)) {
			/* mark AUR as unusable */
			free(options.url);
			options.url = NULL;
		}
		// g_slist_free_full(alist, freeit);
	}

	if (options.analyses & PACANA_ANALYSIS_SHADOW) {
		OPRINTF(1, "Performing SHADOW analysis:\n");
		/* skip local database */
		for (s = slist->next; s; s = s->next) {
			dbhash = s->data;
			alpm_list_t *p;

			for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
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
			alpm_list_t *p;

			for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
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
			alpm_list_t *p;

			for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
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
	if (options.analyses & PACANA_ANALYSIS_STRANDED) {
		OPRINTF(1, "Performing STRANDED analysis:\n");
		if (options.url) {
			/* local database */
			if ((s = slist)) {
				dbhash = s->data;

				alpm_list_t *p;

				for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
					alpm_pkg_t *pkg = p->data;

					check_stranded_local(s, pkg);
				}
			}
			/* skip local database */
			for (s = slist->next; s; s = s->next) {
				dbhash = s->data;

				if (!dbhash->custom)
					continue;
				alpm_list_t *p;

				for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
					alpm_pkg_t *pkg = p->data;

					check_stranded_custom(s, pkg);
				}
			}
		}
		OPRINTF(1, "Done\n\n");
	}
	if (options.analyses & PACANA_ANALYSIS_AURCHECK) {
		OPRINTF(1, "Performing AURCHECK analysis:\n");
		WPRINTF("TODO!\n");
		OPRINTF(1, "Done\n\n");
	}
	if (options.analyses & PACANA_ANALYSIS_MISSING) {
		OPRINTF(1, "Performing MISSING analysis:\n");
		for (s = slist; s; s = s->next) {
			dbhash = s->data;
			alpm_list_t *p;
			for (p = dbhash->pkgs; p; p = alpm_list_next(p)) {
				alpm_pkg_t *pkg = p->data;

				check_missing(s, pkg);
			}
		}
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
Copyright (c) 2010-2021  Monavacon Limited <http://www.monavacon.com/>\n\
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
Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021  Monavacon Limited.\n\
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
	if ((analyses & PACANA_ANALYSIS_STRANDED) && options.url) {
		if (*buf)
			strcat(buf, ",");
		strcat(buf, "stranded");
	}
	if ((analyses & PACANA_ANALYSIS_AURCHECK) && options.url) {
		if (*buf)
			strcat(buf, ",");
		strcat(buf, "aurcheck");
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
    -a, --aur [URL]\n\
        specify analysis to include AUR at URL [default: %4$s]\n\
    -w, --which WHICH[,[!]WHICH]...\n\
        specify which analyses to perform [default: %5$s]\n\
    -r, --repos REPOSITORY[,[!]REPOSITORY]...\n\
        specify which repositories to analyze [default: %6$s]\n\
    -c, --custom CUSTOM[,[!]CUSTOM]...\n\
        specify which repositories are custom [default: %7$s]\n\
  General Options:\n\
    -n, --dryrun\n\
        do not access AUR but print what would be done [default: %8$s]\n\
    -D, --debug [LEVEL]\n\
        increment or set debug LEVEL [default: '%2$d']\n\
    -v, --verbose [LEVEL]\n\
        increment or set output verbosity LEVEL [default: '%3$d']\n\
        this option may be repeated.\n\
", argv[0]
	, options.debug
	, options.output
	, (options.url ? : "disabled")
	, show_analyses(options.analyses)
	, (options.repos ? : "all")
	, (options.custom ? : "custom")
	, (options.dryrun ? "enabled" : "disabled")
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
			{"aur",		optional_argument,	NULL, 'a'},
			{"which",	required_argument,	NULL, 'w'},
			{"repos",	required_argument,	NULL, 'r'},
			{"custom",	required_argument,	NULL, 'c'},

			{"dryrun",	no_argument,		NULL, 'n'},
			{"debug",	optional_argument,	NULL, 'D'},
			{"verbose",	optional_argument,	NULL, 'v'},
			{"help",	no_argument,		NULL, 'h'},
			{"version",	no_argument,		NULL, 'V'},
			{"copying",	no_argument,		NULL, 'C'},
			{"?",		no_argument,		NULL, 'H'},
			{ 0, }
		};
		/* *INDENT-ON* */

		c = getopt_long_only(argc, argv, "Aa::w:r:c:nD::v::hVCH?", long_options,
				&option_index);
#else				/* defined _GNU_SOURCE */
		c = getopt(argc, argv, "Aa:w:r:c:nDvhVC?");
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
		case 'a':	/* -a, --aur [URL] */
			free(options.url);
			options.url = strdup(optarg ? : AUR_DEFAULT_URL);
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
				if (!strcasecmp(p, "stranded")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_STRANDED;
					} else {
						options.analyses |= PACANA_ANALYSIS_STRANDED;
					}
					continue;
				}
				if (!strcasecmp(p, "aurcheck")) {
					if (options.debug)
						fprintf(stderr, "%s: found token '%s'\n", argv[0], p);
					if (reverse) {
						options.analyses &= ~PACANA_ANALYSIS_AURCHECK;
					} else {
						options.analyses |= PACANA_ANALYSIS_AURCHECK;
					}
					continue;
				}
				goto bad_option;
			}
			if (options.debug)
				fprintf(stderr, "%s: analyses specified(0x%lx): %s\n", argv[0], options.analyses, show_analyses(options.analyses));
			break;
		case 'r':	/* -r, --repos [!]REPO[,[!]REPO]... */
			free(options.repos);
			options.repos = strdup(optarg);
			break;
		case 'c':	/* -c, --custom [!]CUSTOM[,[!]CUSTOM]... */
			free(options.custom);
			options.custom = strdup(optarg);
			break;
		case 'n':	/* -n, --dryrun */
			options.dryrun = 1;
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
