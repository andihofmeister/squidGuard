/*
 * By accepting this notice, you agree to be bound by the following
 * agreements:
 *
 * This software product, squidGuard, is copyrighted
 * (C) 2012, Andreas Hofmeister, Collax GmbH,
 * (C) 1998-2009 by Christine Kronberg, Shalla Secure Services.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License (version 2) as
 * published by the Free Software Foundation.  It is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License (GPL) for more details.
 *
 * You should have received a copy of the GNU General Public License
 * (GPL) along with this program.
 */

#define _GNU_SOURCE

#include "sg.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <db.h>
#include <errno.h>
#include <ctype.h>

#include "sgDb.h"
#include "sgMemory.h"
#include "sgLog.h"

#define DATABASE        NULL

extern int globalUpdate;
extern char *globalCreateDb;
extern int showBar;     /* from main.c */

struct sgDb {
	char *	dbhome;
	DB *	dbp;
	int	entries;
	int	type;
};

/*
 * domainCompare does a reverse compare of two strings
 */
/*static*/ int domainCompare(DB *dbp, const DBT *a, const DBT *b)
{
	register const char *a1, *b1;
	register char ac1, bc1;

	a1 = (char *)a->data + a->size - 1;
	b1 = (char *)b->data + b->size - 1;
	while (*a1 == *b1) {
		if (b1 == b->data || a1 == a->data)
			break;
		a1--; b1--;
	}
	ac1 = *a1 == '.' ? '\1' : *a1;
	bc1 = *b1 == '.' ? '\1' : *b1;
	if (a1 == a->data && b1 == b->data)
		return ac1 - bc1;
	if (a1 == a->data)
		return -1;
	if (b1 == b->data)
		return 1;
	return ac1 - bc1;
}

static int sgStrRncmp(const char *a, const char *b, int blen)
{
	const char *a1 = (char *)strchr(a, '\0');
	const char *b1 = (char *)strchr(b, '\0');

	while (blen > 0 && *a1 == *b1) {
		if (b1 == b || a1 == a)
			break;
		a1--; b1--; blen--;
	}
	if (a1 == a && b1 == b)
		return *a1 - *b1;
	if (blen == 0)
		return *a1 - *b1;
	if (a1 == a)
		return -1;
	if (b1 == b)
		return 1;
	return *a1 - *b1;
}

static char *sgStripUrl(const char *url)
{
	char *newurl;
	const char *p = url;
	const char *d = NULL;
	const char *a = NULL;
	const char *e = NULL;

	newurl = sgMalloc(strlen(url) + 1);

	p = url;
	d = strchr(p, '/');     /* find domain end */
	e = d;
	a = strchr(p, '@');     /* find auth  */
	if (a != NULL && (a < d || d == NULL))
		p = a + 1;
	a = strchr(p, ':'); /* find port */;
	if (a != NULL && (a < d || d == NULL))
		e = a;
	if (e == NULL) {
		strcpy(newurl, p);
	} else {
		strncpy(newurl, p, e - p);
		*(newurl + (e - p)) = '\0';
	}
	if (d != NULL)
		strcat(newurl, d);

	return newurl;
}


#if DB_VERSION_MAJOR < 4
#define DBOPEN(dbp, txnid, dbfile, database, dbmode, flag, fmode) \
	open(dbp, dbfile, database, dbmode, flag, fmode)
#else
#define DBOPEN(dbp, txnid, dbfile, database, dbmode, flag, fmode) \
	open(dbp, txnid, dbfile, database, dbmode, flag, fmode)
#endif

struct sgDb *sgDbInit(int type, char *file)
{
	struct stat st, st2;
	char *dbfile = NULL;
	char *update = NULL;
	int createdb = 0, ret;
	u_int32_t flag = 0;
	struct sgDb *Db;

	if ((Db = sgMalloc(sizeof(struct sgDb))) == NULL)
		return NULL;

	Db->type = type;

	if (file != NULL) {
		if (globalCreateDb != NULL && (!strcmp(globalCreateDb, "all") ||
					       !sgStrRncmp(file, globalCreateDb, strlen(globalCreateDb))))
			createdb = 1;
		dbfile = sgMalloc(strlen(file) + 5);
		strcpy(dbfile, file);
		strcat(dbfile, ".db");
		if (stat(dbfile, &st) == 0) {
			if (stat(file, &st2) == 0)
				if (st.st_mtime >= st2.st_mtime)
					createdb = 0;

			if (!createdb)
				sgLogInfo("loading dbfile %s", dbfile);
		} else {
			if (!createdb) {
				sgFree(dbfile);
				dbfile = NULL;
			}
		}
	}

	Db->entries = 1;
	if ((ret = db_create(&Db->dbp, NULL, 0)) != 0) {
		sgLogFatal("FATAL: Error db_create: %s", strerror(ret));
		sgFree(dbfile);
		sgFree(Db);
		return NULL;
	}

	/*please feel free to experiment with cacesize and pagesize */
	//Db->dbp->set_cachesize(Db->dbp, 0, 1024 * 1024,0);
	//Db->dbp->set_pagesize(Db->dbp, 1024);

	if (Db->type == SGDBTYPE_DOMAINLIST)
		Db->dbp->set_bt_compare(Db->dbp, domainCompare);

	if (globalUpdate || createdb || (dbfile != NULL && stat(dbfile, &st))) {
		flag = DB_CREATE;
		if (createdb)
			flag = flag | DB_TRUNCATE;
		if ((ret = Db->dbp->DBOPEN(Db->dbp, NULL, dbfile, NULL, DB_BTREE, flag, 0664)) != 0) {
			sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
			goto error_out;
		}
	} else {
		if ((ret = Db->dbp->DBOPEN(Db->dbp, NULL, dbfile, NULL, DB_BTREE, DB_CREATE, 0664)) != 0) {
			sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
			goto error_out;
		}
	}

	if (file != NULL) {
		if (dbfile == NULL) {
			sgDbLoadTextFile(Db, file, 0);
			if (Db->entries == 0)
				goto error_out;
		}
		if (dbfile != NULL && createdb) {
			sgDbLoadTextFile(Db, file, 0);
			if (Db->entries == 0) {
				sgLogNotice("no entries in %s", dbfile);
				goto error_out;
			} else {
				sgLogInfo("created new dbfile %s", dbfile);
				(void)Db->dbp->sync(Db->dbp, 0);
			}
		}
		if (globalUpdate) {
			if (dbfile == NULL) {
				sgLogError("ERROR: update dbfile %s.db. file does not exists, use -C to create", file);
			} else {
				update = sgMalloc(strlen(file) + 6);
				strcpy(update, file);
				strcat(update, ".diff");
				if (stat(update, &st) == 0) {
					sgLogInfo("update dbfile %s", dbfile);
					sgDbLoadTextFile(Db, update, 1);
				}
				(void)Db->dbp->sync(Db->dbp, 0);
			}
		}
	}

	sgFree(dbfile);

	return Db;

error_out:
	sgFree(dbfile);
	sgFree(Db);
	return NULL;
}

void freeDb(struct sgDb *db)
{
	if (db == NULL)
		return;

	if (db->dbp) {
		db->dbp->close(db->dbp, 0);
		db->dbp = NULL;
	}

	sgFree(db);
}

static char *key2str(const DBT *dbt)
{
	char *result = sgMalloc(dbt->size + 1);

	strncpy(result, dbt->data, dbt->size);
	result[dbt->size] = 0;
	return result;
}

int sgDbSearch(struct sgDb *Db, const char *request, void **rdata, size_t *rlen)
{
	int dberror = 0;
	int result = 0;
	int again = 0;
	u_int32_t dbmethod = DB_SET_RANGE;
	char *r = NULL;

	DBC *dbcp = NULL;
	DBT key, data;

	memset(&key, 0, sizeof(key));
	// key.flags = DB_DBT_MALLOC;
	memset(&data, 0, sizeof(data));
	data.flags = DB_DBT_MALLOC;

	if ((dberror = Db->dbp->cursor(Db->dbp, NULL, &dbcp, 0)) != 0) {
		sgLogFatal("cursor: %s", strerror(dberror));
		return 9;
	}

	switch (Db->type) {
	case SGDBTYPE_DOMAINLIST:
		asprintf(&r, ".%s", request);
		dbmethod = DB_SET_RANGE;
		break;
	case SGDBTYPE_USERLIST:
		r = strdup(request);
		dbmethod = DB_SET;
		break;
	default:
		r = strdup(request);
		dbmethod = DB_SET_RANGE;
		break;
	}

	key.data = r;
	key.size = strlen(r);

	dberror = dbcp->c_get(dbcp, &key, &data, dbmethod);

	sgLogDebug("first search '%s': %d", r, dberror);

	switch (dberror) {
	case 0: {
		char *newkey = key2str(&key);
		sgLogDebug("  found, key is now '%s'", newkey);

		if (Db->type == SGDBTYPE_USERLIST) {
			result = 1;
		} else {
			if (strncmp(r, newkey, key.size) == 0) {
				sgLogDebug("  exact match");
				result = 1;
			} else {
				again = 1;
				dbmethod = DB_PREV;
			}
		}
		sgFree(newkey);
		break;
	}

	case DB_NOTFOUND:
		if (Db->type == SGDBTYPE_USERLIST) {
			result = 0;
		} else {
			again = 1;
			dbmethod = DB_LAST;
		}
		break;
	}
	;

	sgFree(data.data);
	data.data = NULL;
	data.size = 0;

	if (!result && again) {
		char *newkey = NULL;

		sgLogDebug("search again");
		again = 0;

		dberror = dbcp->c_get(dbcp, &key, &data, dbmethod);
		newkey = key2str(&key);

		switch (dberror) {
		case 0:
			sgLogDebug("  found, key is now '%s'", newkey);
			if (Db->type == SGDBTYPE_DOMAINLIST) {
				if ((sgStrRncmp(newkey, r, key.size)) == 0)
					result = 1;
			} else {
				if ((strncmp(newkey, r, key.size)) == 0)
					result = 1;
			}
			break;

		case DB_NOTFOUND:
			sgLogDebug("  not found, key is now '%s'", newkey);
			break;
		}
		;

		sgFree(newkey);
	}

	(void)dbcp->c_close(dbcp);

	sgFree(r);

	if (result) {
		if (rdata != NULL) {
			*rdata = data.data;
			if (rlen != NULL)
				*rlen = data.size;
		} else {
			sgFree(data.data);
		}
	} else {
		sgFree(data.data);
	}

	return result;
}

int sgDbLookup(struct sgDb *Db, const char *request, void **rdata, size_t *rlen)
{
	int dberr = 0;
	int result = 0;

	DBT dbkey, dbdata;

	memset(&dbkey, 0, sizeof(dbkey));
	memset(&dbdata, 0, sizeof(dbdata));

	dbkey.data = (char *)request;
	dbkey.size = strlen(request);

	dberr = Db->dbp->get(Db->dbp, NULL, &dbkey, &dbdata, 0);
	if (dberr == 0) {
		result = 1;
		if (rdata != NULL)
			*rdata = dbdata.data;
		if (rlen != NULL)
			*rlen = dbdata.size;
	} else {
		result = 0;
		if (rdata != NULL)
			*rdata = NULL;
		if (rlen != NULL)
			*rlen = 0;
	}

	return result;
}

int defined(struct sgDb *Db, const char *request)
{
	return sgDbLookup(Db, request, NULL, NULL);
}

static int stdoutisatty;

void startProgressBar()
{
	stdoutisatty = isatty(STDOUT_FILENO);

	if (1 == stdoutisatty) {
		/* do nothing */
	} else {
		printf("    [");
		fflush(stderr);
	}
	return;
}

void finishProgressBar()
{
	if (1 == stdoutisatty)
		printf("\n");
	else
		printf("] 100 %% done\n");
	fflush(stderr);
	return;
}

void updateProgressBar(float prog)
{
	if (1 == stdoutisatty) {
		int j, k = 0;
		k = (int)(prog * 50.0);
		printf("\r"); fflush(stderr);
		printf("    [");
		for (j = 0; j < 50; j++) {
			if (j <= k)
				printf("=");
			else
				printf(" ");
		}
		printf("] %d %% done", (int)(prog * 100.0)); fflush(stderr);
	} else {
		if (((int)(prog * 100.0) % 100) == 0)
			printf("."); fflush(stderr);
	}

	return;
}

void sgDbLoadTextFile(struct sgDb *Db, char *filename, int update)
{
	char line[MAX_BUF];
	FILE *fp;
	int added = 0, deleted = 0;
	off_t fpsz;
	off_t lnsz = 0;
	struct stat fpst;

	sgLogDebug("Processing file %s", filename);

	if ((fp = fopen(filename, "r")) == NULL) {
		sgLogError("%s: %s", filename, strerror(errno));
		return;
	} else {
		if (showBar == 1)
			printf("Processing file and database %s\n", filename);
	}

	fstat(fileno(fp), &fpst);
	fpsz = fpst.st_size;

	if (showBar == 1)
		startProgressBar();

	while (fgets(line, sizeof(line), fp) != NULL) {
		int add = 0;
		char *key = NULL;
		char *val = NULL;
		char *p = NULL;
		char *k;
		char *nkey = NULL;

		lnsz += strlen(line);
		if (showBar == 1)
			updateProgressBar((float)lnsz / (float)fpsz);

		if (*line == '#')
			continue;

		p = strchr(line, '\n');
		if (p != NULL && p != line) {
			if (*(p - 1) == '\r') /* removing ^M  */
				p--;
			*p = '\0';
		}

		key = line;
		if (*key == '+' || *key == '-') {
			if (*key == '+')
				add = 1;
			else
				add = 0;
			key++;
		}

		if ((key = strtok(key, " \t\n")) == NULL)
			continue;

		if (key == NULL)
			continue;

		for (p = key; *p != '\0'; p++) /* convert key to lowercase chars */
			*p = tolower(*p);


		val = strtok(NULL, "\n");
		if (val != NULL) {
			/* remove extra space before the redirect url */
			while (*val != '\0' && isspace(*val))
				val++;

			if (*val == '\0') /* there was nothing but some trailing space */
				val = NULL;
		}

		if (Db->type == SGDBTYPE_DOMAINLIST) {
			nkey = sgMalloc(strlen(key) + 2);
			nkey[0] = '.'; nkey[1] = '\0';
			strcat(nkey, key);
			k = nkey;
		} else if (Db->type == SGDBTYPE_URLLIST) {
			if (*key != '.') {
				nkey = sgStripUrl(key);
				k = nkey;
			} else {
				k = key;
			}
		} else {
			k = key;
		}

		if (update && !add) {
			DBT dbkey;
			memset(&dbkey, 0, sizeof(DBT));

			dbkey.data = k;
			dbkey.size = strlen(k);

			errno = Db->dbp->del(Db->dbp, NULL, &dbkey, 0);

			deleted++;
			Db->entries--;
		} else {
			if (sgDbUpdate(Db, k, val, (val ? strlen(val) : 0)))
				added++;
			else
				sgLogFatal("FATAL: sgDbLoadTextFile: put: %s", strerror(errno));
		}

		sgFree(nkey);
		nkey = NULL;
	}

	sgLogInfo("update: added %d entries, deleted %d entries", added, deleted);
	sgLogInfo("DB has %d entries now", Db->entries);

	if (showBar == 1)
		finishProgressBar();

	fclose(fp);
}


int sgDbUpdate(struct sgDb *Db, const char *key, void *value, size_t len)
{
	u_int32_t flags = 0;
	int result = 1;

	DBT dbkey, dbdata;

	memset(&dbkey, 0, sizeof(DBT));
	memset(&dbdata, 0, sizeof(DBT));

	dbkey.data = (void *)key;
	dbkey.size = strlen(key);

	if (value == NULL) {
		char *def = "";
		dbdata.data = def;
		dbdata.size = strlen(def);
		flags = DB_NOOVERWRITE;
	} else {
		dbdata.data = value;
		dbdata.size = len;
		dbdata.flags = DB_DBT_MALLOC;
		flags = 0;
	}
	switch (errno = Db->dbp->put(Db->dbp, NULL, &dbkey, &dbdata, flags)) {
	case 0:
		Db->entries++;
		break;
	case DB_KEYEXIST:
		sgLogError("%s: key already exists", key);
		break;
	default:
		sgLogFatal("FATAL: sgDbUpdate: put: %s", strerror(errno));
		result = 0;
		break;
	}

	return result;
}
