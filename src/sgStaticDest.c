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

#include "sgMatch.h"
#include "sgDestList.h"
#include "sgStaticDest.h"

static int matchAny(void *priv, const struct SquidInfo *info)
{
	return 1;
}

static struct DestMatch *newAnyDestMatch()
{
	return sgNewDestMatch(matchAny, NULL);
}

static int matchInAddr(void *priv, const struct SquidInfo *info)
{
	return info->isAddress;
}

static struct DestMatch *newInAddrMatch()
{
	return sgNewDestMatch(matchInAddr, NULL);
}

void makeStaticDestLists()
{
	struct DestList *now = NULL;

	if ((now = findDestList("any")) == NULL) {
		now = newDestList("any");
		addDestListMatch(now, newAnyDestMatch());
	}

	if ((now = findDestList("all")) == NULL) {
		now = newDestList("all");
		addDestListMatch(now, newAnyDestMatch());
	}

	if ((now = findDestList("none")) == NULL) {
		/* there is a hack in sgAccessList.c for this */
		now = newDestList("none");
		addDestListMatch(now, newAnyDestMatch());
	}

	if ((now = findDestList("in-addr")) == NULL) {
		now = newDestList("in-addr");
		addDestListMatch(now, newInAddrMatch());
	}
}
