/*
 * By accepting this notice, you agree to be bound by the following
 * agreements:
 *
 * This software product, squidGuard, is copyrighted (C) 1998-2009
 * by Christine Kronberg, Shalla Secure Services. All rights reserved.
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

#include "sg.h"
#include "sgMemory.h"
#include "sgLog.h"

#define DATABASE        NULL

extern int globalUpdate;
extern char *globalCreateDb;
extern int showBar;     /* from main.c */

static int domainCompare(const DB *, const DBT *, const DBT *);

#if DB_VERSION_MAJOR == 4
#define DBOPEN(dbp,txnid,dbfile,database,dbmode,flag,fmode) \
	open(dbp,txnid,dbfile,database,dbmode,flag,fmode)
#else
#define DBOPEN(dbp,txnid,dbfile,database,dbmode,flag,fmode) \
	open(dbp,dbfile,database,dbmode,flag,fmode)
#endif

struct sgDb * sgDbInit(int type, char *file)
{
	struct stat st, st2;
	char *dbfile = NULL;
	char *update = NULL;
	int createdb = 0, ret;
	u_int32_t flag = 0;
	struct sgDb * Db;

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
				sgLogNotice("INFO: loading dbfile %s", dbfile);
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
		Db->dbp->set_bt_compare(Db->dbp, (void *)domainCompare);

	if (globalUpdate || createdb || (dbfile != NULL && stat(dbfile, &st))) {
		flag = DB_CREATE;
		if (createdb)
			flag = flag | DB_TRUNCATE;
		if ((ret = Db->dbp->DBOPEN(Db->dbp, NULL, dbfile, NULL, DB_BTREE, flag, 0664)) != 0) {
			(void)Db->dbp->close(Db->dbp, 0);
			sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
		}
	} else {
		if ((ret = Db->dbp->DBOPEN(Db->dbp, NULL, dbfile, NULL, DB_BTREE, DB_CREATE, 0664)) != 0)
			sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
	}

	if (file != NULL) {
		if (dbfile == NULL) {
			sgDbLoadTextFile(Db, file, 0);
			if (Db->entries == 0) {
				(void)Db->dbp->close(Db->dbp, 0);
			}
		}
		if (dbfile != NULL && createdb) {
			sgDbLoadTextFile(Db, file, 0);
			if (Db->entries == 0) {
				(void)Db->dbp->close(Db->dbp, 0);
			} else {
				sgLogNotice("INFO: create new dbfile %s", dbfile);
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
					sgLogNotice("INFO: update dbfile %s", dbfile);
					sgDbLoadTextFile(Db, update, 1);
				}
				(void)Db->dbp->sync(Db->dbp, 0);
			}
		}
	}
	if (dbfile != NULL)
		sgFree(dbfile);

	return Db;
}

static char * key2str(const DBT * dbt)
{
	char * result = sgMalloc(dbt->size + 1);
	strncpy(result, dbt->data, dbt->size);
	result[dbt->size + 1] = 0;
	return result;
}

static int dbSearch(struct sgDb *Db, const char *request, void **rdata, int *rlen)
{
	int errno, result = 0;
	u_int32_t dbmethod = DB_SET_RANGE;
	char *req = strdup(request);
	char r[MAX_BUF + 1];

	DBC *   dbcp = NULL;
	DBT key, data;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	if ((errno = Db->dbp->cursor(Db->dbp, NULL, &dbcp, 0)) != 0) {
		sgLogFatal("FATAL: cursor: %s", strerror(errno));
		exit(1);
	}

	switch (Db->type) {
		case SGDBTYPE_DOMAINLIST:
			r[0] = '.'; r[1] = '\0';
			strcat(r, request);
			req = r;
			break;
		case SGDBTYPE_USERLIST:
			dbmethod = DB_SET;
			break;
		default:
			break;
	}

	key.data = (char *)req;
	key.size = strlen(req);

	errno = dbcp->c_get(dbcp, &key, &data, dbmethod);

	switch (errno) {
		case EAGAIN:                    /* Deadlock. */
			break;
		case 0: {                       /* Success. */
			char * data1 = key2str(&key);

			if (strncmp(req, data1, key.size) == 0) {
				result = 1;
			} else {
				switch (errno = dbcp->c_get(dbcp, &key, &data, DB_PREV)) {
					case DB_NOTFOUND:
						errno = dbcp->c_get(dbcp, &key, &data, DB_FIRST);
						/* ONTOP */
						break;
					case 0: {
						char * data2 = key2str(&key);
						/* PPREV */
						if (Db->type == SGDBTYPE_DOMAINLIST) {
							if ((sgStrRncmp(data1, data2, key.size) != 0) &&
							    (!sgStrRncmp(data2, req, key.size)))
								result = 1;
						} else {
							if ((strncmp(data1, data2, key.size) != 0) &&
							    (!strncmp(data2, req, key.size)))
								result = 1;
						}
						sgFree(data2);
					}
				}
			}
			sgFree(data1);
			break;
		}

		case DB_NOTFOUND:           /* Not found. */
			if (Db->type == SGDBTYPE_USERLIST) {
				result = 0;
				break;
			}
			switch (errno = dbcp->c_get(dbcp, &key, &data, DB_LAST)) {
				case DB_NOTFOUND:
					result = DB_NOTFOUND;
					break;
				case 0: {
					char * data1 = sgMalloc(key.size + 1);
					strncpy(data1, key.data, key.size);
					if (Db->type == SGDBTYPE_DOMAINLIST) {
						if (!sgStrRncmp(data1, req, key.size))
							result = 1;
					} else {
						if (!strncmp(data1, req, key.size))
							result = 1;
					}
					sgFree(data1);
					break;
				}
			}
			break;
	}

	sgFree(req);
	(void)dbcp->c_close(dbcp);

	if (rdata != NULL)
		*rdata = data.data;
	if (rlen != NULL)
		*rlen = data.size;

	return result;
}

int defined(struct sgDb *Db, const char *request)
{
	return dbSearch(Db, request, NULL, NULL);
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
	DB *dbp;
	char *key, *val, *p, line[MAX_BUF];
	char *k, nkey[MAX_BUF + 1];
	FILE *fp;
	int entries = 0, added = 0, add = 0, deleted = 0;
	size_t fpsz;
	size_t lnsz = 0;
	struct stat fpst;
	DBT dbkey, dbdata;

	memset(&dbkey, 0, sizeof(DBT));
	memset(&dbdata, 0, sizeof(DBT));

	dbp = Db->dbp;
	Db->entries = 0;
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
		key = strtok(key, " \t\n");
		if (key == NULL) {
			continue;
		} else {
			val = strtok(NULL, "\n");
			if (val != NULL) {
				/* remove extra space before the redirect url */
				while (*val != '\0' && isspace(*val))
					val++;
				if (*val == '\0') /* there was nothing but some trailing space */
					val = NULL;
			}
		}
		for (p = key; *p != '\0'; p++) /* convert key to lowercase chars */
			*p = tolower(*p);
		if (Db->type == SGDBTYPE_DOMAINLIST) {
			nkey[0] = '.'; nkey[1] = '\0';
			strcat(nkey, key);
			k = nkey;
		} else if (Db->type == SGDBTYPE_URLLIST) {
			if (*key != '.')
				k = sgStripUrl(key);
			else
				k = key;
		} else {
			k = key;
		}
		dbkey.data = k;
		dbkey.size = strlen(k);
		if (val == NULL) {
			dbdata.data = "";
			dbdata.size = 1;
		} else {
			dbdata.data = val;
			dbdata.size = strlen(val);
		}
		if (update && !add) {
			errno = dbp->del(dbp, NULL, &dbkey, 0);
			deleted++;
			entries--;
		} else {
			switch (errno = dbp->put(dbp, NULL, &dbkey, &dbdata, 0)) {
			case 0:
				added++;
			/*FALLTHROUGH*/
			case DB_KEYEXIST:
				entries++;
				break;
			default:
				sgLogFatal("FATAL: sgDbLoadTextFile: put: %s", strerror(errno));
				break;
			}
		}
	}
	if (update)
		sgLogNotice("INFO: update: added %d entries, deleted %d entries", added, deleted);
	if (showBar == 1)
		finishProgressBar();
	Db->entries = entries;
	fclose(fp);
}


void sgDbUpdate(struct sgDb *Db, char *key, char *value, size_t len)
{
	DB *dbp;
	u_int32_t flags = DB_NOOVERWRITE;
	char key_buf[MAX_BUF];
	char value_buf[MAX_BUF];
	dbp = Db->dbp;

	DBT dbkey, dbdata;

	memset(&dbkey, 0, sizeof(DBT));
	memset(&dbdata, 0, sizeof(DBT));

	strcpy(key_buf, key);
	dbkey.data = key_buf;
	dbkey.size = strlen(key);
	if (value == NULL) {
		dbdata.data = "default";
		dbdata.size = 8;
	} else {
		if (len > sizeof(value_buf))
			sgLogFatal("FATAL: Buffer too large in sgDbUpdate()");
		memcpy(value_buf, value, len);
		dbdata.data = value_buf;
		dbdata.size = len;
		flags = 0;
	}
	switch (errno = dbp->put(dbp, NULL, &dbkey, &dbdata, flags)) {
	case 0:
		break;
	case DB_KEYEXIST:
		/*sgLogError("ERROR: %s: key already exists", key_buf);*/
		break;
	default:
		sgLogFatal("FATAL: sgDbUpdate: put: %s", strerror(errno));
		break;
	}
}

/*
 * domainCompare does a reverse compare of two strings
 */

static int domainCompare(const DB *dbp, const DBT *a, const DBT *b)
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

