/*
 * By accepting this notice, you agree to be bound by the following
 * agreements:
 *
 * This software product, squidGuard, is copyrighted
 * (C) 2012, Andreas Hofmeister, Collax GmbH,
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
#include <netdb.h>

#include "sgNetGroup.h"
#include "sgLog.h"
#include "sgMemory.h"

extern int groupDebug;

#define dprintf(...)    if (groupDebug) sgLogError(__VA_ARGS__)
#define dputs(s)        if (groupDebug) sgLogError("%s", s)

struct node {
	struct node *	next;
	char *		name;
};

static void freeNetgroupMatch(void *o)
{
	sgFree(o);
}

static int netgroupUserMatch(void *priv, const struct SquidInfo *info)
{
	if (innetgr((char *)priv, NULL, info->ident, NULL)) {
		sgLogDebug("user '%s' is in netgroup %s", info->ident, priv);
		return 1;
	}

	return 0;
}

struct SourceMatch *newNetgroupUserMatch(const char *netgroup)
{
	struct SourceMatch *result = NULL;

	sgLogDebug("initialize netgroup user match with group '%s'", netgroup);

	if ((result = sgNewSourceMatch(SOURCE_USER_MATCH, netgroupUserMatch, freeNetgroupMatch)) == NULL)
		return NULL;

	result->priv = sgStrdup(netgroup);

	return result;
}

static int netgroupHostMatch(void *priv, const struct SquidInfo *info)
{
	if (innetgr((char *)priv, NULL, info->domain, NULL)) {
		sgLogDebug("host '%s' is in netgroup %s", info->domain, priv);
		return 1;
	}

	return 0;
}

struct SourceMatch *newNetgroupHostMatch(const char *netgroup)
{
	struct SourceMatch *result = NULL;

	sgLogDebug("initialize netgroup host match with group '%s'", netgroup);

	if ((result = sgNewSourceMatch(SOURCE_DOMAIN_MATCH, netgroupHostMatch, freeNetgroupMatch)) == NULL)
		return NULL;

	result->priv = sgStrdup(netgroup);

	return result;
}
