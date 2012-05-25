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

#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "sgLog.h"
#include "sgSetting.h"
#include "sgMemory.h"
#include "sgSourceList.h"

void addUserToSource(struct SourceList *list, const char *ident)
{
	char *user = sgStrdup(ident);
	char *lc;

	for (lc = user; *lc != '\0'; lc++) /* convert username to lowercase chars */
		*lc = tolower(*lc);

	addUserPermanently(list, user);

	sgLogDebug("Added User: %s", user);

	sgFree(user);
}

static void addUsersFromFp(struct SourceList *list, FILE *fp)
{
	char line[MAX_BUF];

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *p;

		if (*line == '#')
			continue;

		if ((p = strchr(line, '\n')) != NULL) {
			if (p != line) {
				if (*(p - 1) == '\r') /* removing ^M  */
					p--;
				*p = 0;
			}
		}

		p = strtok(line, " \t,");
		do
			addUserToSource(list, p);
		while ((p = strtok(NULL, " \t,")) != NULL);
	}
}

void addUserListToSource(struct SourceList *list, const char *file)
{
	char *filename = NULL;
	FILE *fd;

	if (file[0] == '/') {
		filename = sgStrdup(file);
	} else {
		const char *dbhome = getSetting("dbhome");

		if (dbhome == NULL)
			dbhome = DEFAULT_DBHOME;

		asprintf(&filename, "%s/%s", dbhome, file);
	}

	if ((fd = fopen(filename, "r")) == NULL) {
		sgLogError("can't open userlist %s: %s", filename, strerror(errno));
		return;
	}

	addUsersFromFp(list, fd);

	fclose(fd);
}

void addExecUserListToSource(struct SourceList *list, const char *cmd)
{
	FILE *pInput;

	pInput = popen(cmd, "r");
	if (pInput == NULL) {
		sgLogError("Unable to run execuserlist command: %s", cmd);
		return;
	}

	addUsersFromFp(list, pInput);
	pclose(pInput);
}


void addIpToSource(struct SourceList *list, const char *ip)
{
	addIpPermanently(list, ip);
	sgLogDebug("Added Ip: %s", ip);
}

void addIpListToSource(struct SourceList *list, char *file)
{
	FILE *fd;
	char *filename = NULL;

	char line[MAX_BUF];

	if (file[0] == '/') {
		filename = sgStrdup(file);
	} else {
		const char *dbhome = getSetting("dbhome");
		if (dbhome == NULL)
			dbhome = DEFAULT_DBHOME;

		asprintf(&filename, "%s/%s", dbhome, filename);
	}

	if ((fd = fopen(filename, "r")) == NULL) {
		sgLogError("can't open iplist %s: %s", filename, strerror(errno));
		return;
	}

	sgLogDebug("init iplist %s", filename);
	while (fgets(line, sizeof(line), fd) != NULL) {
		char *p;

		if (*line == '#')
			continue;

		if ((p = strchr(line, '\n')) != NULL) {
			if (p > line && (*(p - 1) == '\r'))
				p--;
			*p = 0;
		}
		if ((p = strchr(line, '#')) != NULL)
			*p = 0;

		p = strtok(line, " \t,");
		do
			addIpToSource(list, p);
		while ((p = strtok(NULL, " \t,")) != NULL);
	}
	fclose(fd);
}
