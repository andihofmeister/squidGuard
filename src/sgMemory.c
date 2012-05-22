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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sgLog.h"
#include "sgMemory.h"


void *sgMalloc(size_t elsize)
{
	void *p;

	if ((p = (void *)malloc(elsize)) == NULL) {
		sgLogFatal("%s", strerror(ENOMEM));
		exit(1);
	}
	memset(p, 0, elsize);
	return (void *)p;
}

void *sgCalloc(size_t nelem, size_t elsize)
{
	void *p;

	if ((p = (void *)calloc(nelem, elsize)) == NULL) {
		sgLogFatal("%s", strerror(ENOMEM));
		exit(1);
	}
	return (void *)p;
}

void *sgRealloc(void *ptr, size_t elsize)
{
	void *p;

	if ((p = (void *)realloc(ptr, elsize)) == NULL) {
		sgLogFatal("%s", strerror(ENOMEM));
		exit(1);
	}
	return (void *)p;
}

char *sgStrdup(const char *in)
{
	char *out;

	if (!in)
		return NULL;

	out = sgMalloc(strlen(in) + 1);
	strcpy(out, in);

	return out;
}

void _sgFree(void *ptr)
{
	free(ptr);
}
