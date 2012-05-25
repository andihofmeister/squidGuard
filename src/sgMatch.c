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

#include "sgMemory.h"
#include "sgMatch.h"

struct SourceMatch *sgNewSourceMatch(int type, source_match_func match, free_func freef)
{
	struct SourceMatch *sm = sgMalloc(sizeof(struct SourceMatch));

	if (sm == NULL)
		return NULL;

	sm->type = type;
	sm->next = NULL;
	sm->match = match;
	sm->free = freef;

	return sm;
}

void freeSourceMatch(struct SourceMatch *sm)
{
	if (sm->free)
		sm->free(sm->priv);
	sgFree(sm);
}

struct DestMatch *sgNewDestMatch(dest_match_func match, free_func freef)
{
	struct DestMatch *dm = sgMalloc(sizeof(struct DestMatch));

	if (dm == NULL)
		return NULL;

	dm->next = NULL;
	dm->match = match;
	dm->free = freef;

	return dm;
}

void freeDestMatch(struct DestMatch *dm)
{
	if (dm->free)
		dm->free(dm->priv);
	sgFree(dm);
}
