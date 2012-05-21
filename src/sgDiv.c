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

#include <string.h>

#include "sg.h"
#include "sgDb.h"
#include "sgLog.h"
#include "sgMemory.h"
#include "sgSetting.h"
#include "HTEscape.h"

/*
 * Reverses cmp of strings
 */
int sgStrRcmp(const char *a, const char *b)
{
	const char *a1 = (char *)strchr(a, '\0');
	const char *b1 = (char *)strchr(b, '\0');

	while (*a1 == *b1) {
		if (b1 == b || a1 == a)
			break;
		a1--; b1--;
	}
	if (a1 == a && b1 == b)
		return *a1 - *b1;
	if (a1 == a)
		return -1;
	if (b1 == b)
		return 1;
	return *a1 - *b1;
}

int sgStrRncmp(const char *a, const char *b, int blen)
{
	const char *a1 = (char *)strchr(a, '\0');
	const char *b1 = (char *)strchr(b, '\0');

	while (*a1 == *b1 && blen > 0) {
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

/*
 *
 * sgDomStrRncmp checks if B is equal to or a subdomain of A
 *
 */
int sgDomStrRcmp(const char *p1, const char *p2)
{
	const char *p11 = (char *)strchr(p1, '\0');
	const char *p22 = (char *)strchr(p2, '\0');

	for (; p11 >= p1 && p22 >= p2 && *p11 == *p22; p11--, p22--) ;
	if (p11 < p1 && p22 < p2)
		return 0;
	if (p22 < p2)
		return -*p11;
	if (p11 < p1 && *p22 == '.')
		return 0;
	return *p11 - *p22;
}
