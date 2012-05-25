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

#include "sgSetting.h"
#include "sgDomainList.h"
#include "sgDb.h"
#include "sgMemory.h"
#include "sgLog.h"

struct DomainListPrivate {
	char *		name;
	struct sgDb *	domainlistDb;
};

static int dlMatch(void *priv, const struct SquidInfo *req)
{
	struct DomainListPrivate *data = (struct DomainListPrivate *)priv;

	sgLogDebug("Looking for domain %s", req->domain);

	if (sgDbSearch(data->domainlistDb, req->domain, NULL, NULL))
		return 1;

	sgLogDebug("domain %s not found in domain list %s", req->domain, data->name);
	return 0;
}

static void dlFree(void *priv)
{
	struct DomainListPrivate *data = (struct DomainListPrivate *)priv;

	sgLogDebug("dlFree() called");
	freeDb(data->domainlistDb);
	sgFree(data->name);
	sgFree(priv);
}

struct DestMatch *newDestDomainListMatch(const char *name, const char *domainlist)
{
	struct DestMatch *result;
	struct DomainListPrivate *priv;
	const char *dbhome = getSetting("dbhome");
	char *filename;

	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;

	if (domainlist == NULL) {
		size_t len = strlen("/dest/") + strlen(name) + strlen("/domainlist") +
			     strlen(dbhome) + strlen("/") + 4;
		filename = sgMalloc(len);
		snprintf(filename, len, "%s/dest/%s/domainlist", dbhome, name);
	} else {
		if (domainlist[0] == '/') {
			filename = sgStrdup(domainlist);
		} else {
			size_t len = strlen(dbhome) + strlen("/") + strlen(domainlist) + 4;
			filename = sgMalloc(len);
			snprintf(filename, len, "%s/%s", dbhome, domainlist);
		}
	}

	sgLogDebug("init domainlist %s", filename);

	if ((priv = sgMalloc(sizeof(struct DomainListPrivate))) == NULL) {
		sgFree(filename);
		return NULL;
	}

	priv->name = NULL;

	if ((priv->domainlistDb = sgDbInit(SGDBTYPE_DOMAINLIST, filename)) == NULL) {
		sgFree(filename);
		sgFree(priv);
		return NULL;
	}

	if ((result = sgNewDestMatch(dlMatch, dlFree)) == NULL) {
		freeDb(priv->domainlistDb);
		sgFree(filename);
		dlFree(priv);
	}

	result->priv = priv;
	priv->name = filename;

	return result;
}
