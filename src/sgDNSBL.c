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

#include <string.h>
#include <stdio.h>
#include <netdb.h>

#include "sgDNSBL.h"
#include "sgMemory.h"
#include "sgLog.h"

static char *strip_fqdn(const char *domain)
{
	char *result;

	result = strstr(domain, ".");
	if (result == NULL)
		return NULL;
	return result + 1;
}

static int is_blacklisted(const char *domain, const char *suffix)
{
	char *target = NULL;
	struct addrinfo *res = NULL;
	int result;

	asprintf(&target, "%s%s.", domain, suffix);

	result = getaddrinfo(target, NULL, NULL, &res);
	sgFree(target);

	if (result == 0) { //Result is defined
		freeaddrinfo(res);
		return 1;
	}

	if (res)
		freeaddrinfo(res);

	sgFree(target);

	//If anything fails (DNS server not reachable, any problem in the resolution,
	//let's not block anything.
	return 0;
}

static int blocked_by_dnsbl(const char *domain, const char *suffix)
{
	const char *dn = domain;

	while ((dn != NULL) && (strchr(dn, '.') != NULL)) { //No need to lookup "com.black.uribl.com"
		sgLogDebug("check %s agains dnsbl %s", dn, suffix);
		if (is_blacklisted(dn, suffix)) {
			sgLogDebug("  %s found on dnsbl", dn);
			return 1;
		}
		dn = strip_fqdn(dn);
	}
	return 0;
}

static int dnsbl_match(void *priv, const struct SquidInfo *req)
{
	return blocked_by_dnsbl(req->domain, (char *)priv);
}

static void free_suffix(void *priv)
{
	sgFree(priv);
}

#define DEFAULT_SUFFIX  ".black.uribl.com"

struct DestMatch *newDNSBLMatch(const char *suffix)
{
	struct DestMatch *dm = NULL;
	char *priv = NULL;

	if ((suffix == NULL) || (*suffix == '\0')) { //Config does not define which dns domain to use
		priv = sgStrdup(DEFAULT_SUFFIX);
	} else {
		if (strspn(suffix, ".-abcdefghijklmnopqrstuvwxyz0123456789") != strlen(suffix))
			sgLogFatal("provided dnsbl \"%s\" doesn't look like a valid domain suffix", suffix);

		priv = sgMalloc(strlen(suffix) + 1);
		*priv = 0;

		if (*suffix != '.')
			strcpy(priv, ".");

		strcat(priv, suffix);
	}

	if ((dm = sgNewDestMatch(dnsbl_match, free_suffix)) == NULL) {
		sgFree(priv);
		return NULL;
	}

	dm->priv = priv;

	return dm;
}
