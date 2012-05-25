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

#include <stddef.h>

#include "sgSourceDomain.h"
#include "sgDb.h"
#include "sgMemory.h"
#include "sgMatch.h"
#include "sgRequest.h"
#include "sgLog.h"


struct SourceDomainPrivate {
	struct sgDb *db;
};

static struct SourceDomainPrivate *newSourceDomainPrivate()
{
	struct SourceDomainPrivate *result = sgMalloc(sizeof(struct SourceDomainPrivate));

	result->db = sgDbInit(SGDBTYPE_DOMAINLIST, NULL);

	return result;
}

static void freeSourceDomainPrivate(void *priv)
{
	freeDb(((struct SourceDomainPrivate *)priv)->db);
	sgFree(priv);
}


static int doSourceDomainMatch(void *priv, const struct SquidInfo *req)
{
	struct sgDb *db = ((struct SourceDomainPrivate *)priv)->db;

	sgLogDebug("looking for source domain %s", req->srcDomain);

	return sgDbSearch(db, req->srcDomain, NULL, NULL);
}

struct SourceMatch *newSourceDomainMatch()
{
	struct SourceDomainPrivate *priv;
	struct SourceMatch *result;

	result = sgNewSourceMatch(SOURCE_DOMAIN_MATCH, doSourceDomainMatch, freeSourceDomainPrivate);

	if (result == NULL)
		return NULL;

	if ((priv = newSourceDomainPrivate()) == NULL) {
		freeSourceMatch(result);
		return NULL;
	}

	result->priv = priv;

	return result;
}

void addDomainToSourceDomainMatch(struct SourceMatch *src, const char *domain)
{
	struct SourceDomainPrivate *priv = (struct SourceDomainPrivate *)(src->priv);

	sgDbUpdate(priv->db, domain, NULL, 0);
}
