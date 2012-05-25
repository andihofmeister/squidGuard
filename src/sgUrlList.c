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

#include <string.h>
#include <stdio.h>

#include "sg.h"
#include "sgSetting.h"
#include "sgMatch.h"
#include "sgMemory.h"
#include "sgDb.h"
#include "sgLog.h"

struct UrlListPrivate {
	char *		name;
	struct sgDb *	urllistDb;
};

static int ulMatch(void *priv, const struct SquidInfo *req)
{
	struct UrlListPrivate *data = (struct UrlListPrivate *)priv;
	int result = 0;

	result = sgDbSearch(data->urllistDb, req->surl, NULL, NULL);

	if (!result)
		result = sgDbSearch(data->urllistDb, req->furl, NULL, NULL);

	if (!result)
		result = sgDbSearch(data->urllistDb, req->domain, NULL, NULL);

	if (result) {
		sgLogDebug("url found in url list %s", data->name);
		return 1;
	} else {
		sgLogDebug("url not found in url list %s", data->name);
		return 0;
	}
}

static void ulFree(void *priv)
{
	struct UrlListPrivate *data = (struct UrlListPrivate *)priv;

	freeDb(data->urllistDb);
	sgFree(data->name);
	sgFree(priv);
}

struct DestMatch *newDestUrlListMatch(const char *name, const char *urllist)
{
	struct DestMatch *result;
	struct UrlListPrivate *priv;
	const char *dbhome = getSetting("dbhome");
	char *filename;

	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;

	if (urllist == NULL) {
		size_t len = strlen("/dest/") + strlen(name) + strlen("/urllist") +
			     strlen(dbhome) + strlen("/") + 4;
		filename = sgMalloc(len);
		snprintf(filename, len, "%s/dest/%s/urllist", dbhome, name);
	} else {
		if (urllist[0] == '/') {
			filename = sgStrdup(urllist);
		} else {
			size_t len = strlen(dbhome) + strlen("/") + strlen(urllist) + 4;
			filename = sgMalloc(len);
			snprintf(filename, len, "%s/%s", dbhome, urllist);
		}
	}

	sgLogDebug("init urllist %s", filename);

	if ((priv = sgMalloc(sizeof(struct UrlListPrivate))) == NULL) {
		sgFree(filename);
		return NULL;
	}

	if ((priv->urllistDb = sgDbInit(SGDBTYPE_URLLIST, filename)) == NULL) {
		sgFree(filename);
		sgFree(priv);
		return NULL;
	}

	if ((result = sgNewDestMatch(ulMatch, ulFree)) == NULL) {
		freeDb(priv->urllistDb);
		sgFree(filename);
		ulFree(priv);
	}

	result->priv = priv;
	priv->name = filename;

	return result;
}
