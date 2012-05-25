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
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

#include "sgLog.h"
#include "sgMemory.h"
#include "sgSetting.h"
#include "sgRequest.h"
#include "HTEscape.h"

#include <netdb.h>
#include <arpa/inet.h>

static int reverselookup = 0;
static int stripRealm = 0;
static char * realm = NULL;
static int serial = 1;

void setReverseLookup(const char *value)
{
	reverselookup = booleanSetting(value);
}

void setStripRealm(const char *value)
{
	stripRealm = booleanSetting(value);
}

void setRealmToStrip(const char *value)
{
	if (realm)
		sgFree(realm);
	realm = sgStrdup(value);

	stripRealm = 1;
}

static void resetSquidInfo(struct SquidInfo *s)
{
	s->serial = serial ++;

	s->protocol[0] = '\0';
	s->domain[0] = '\0';
	s->isAddress = 0;
	s->url[0] = '\0';
	s->orig[0] = '\0';
	s->surl[0] = '\0';
	s->furl[0] = '\0';
	s->port = 0;
	s->src[0] = '\0';
	s->srcDomain[0] = '\0';
	s->ident[0] = '\0';
	s->method[0] = '\0';
}

static int parseUrl(char *url, struct SquidInfo *s)
{
	char *p = NULL;
	char *d = NULL;
	size_t l = 0;
	size_t n = 0;
	char *domain = NULL;
	char *sdomain = NULL;

	char *pathcp = sgStrdup(url);

	memset(pathcp, 0, strlen(url));

	strncpy(s->orig, url, sizeof(s->orig));

	/* Now convert url to lowercase chars */
	for (p = url; *p != '\0'; p++)
		*p = tolower(*p);

	if ((p = strstr(url, "://")) == NULL) {
		strcpy(s->protocol, "unknown");
		p = url;
	} else {
		*p = 0;
		strcpy(s->protocol, url);
		p += 3;
	}

	/* p points to the begining of the host part, find first slash that ends it */
	domain = p;
	if ((d = strchr(p, '/')) != NULL) {
		p = d + 1;
		*d = 0;
	} else {
		p = NULL;
	}

	/* p now is either NULL or points to the first char in the path part*/
	if (p != NULL) {
		char *to = pathcp;
		char *from = p;

		/* skip leading slashes */
		while (*from == '/')
			from++;

		while (*from != 0 && *from != '?') {
			/* skip double slashes */
			if (*from == '/' && *(from + 1) == '/') {
				from++;
				continue;
			}
			*to = *from;
			to++; from++;
		}

		/* keep the query part when present */
		if (*from == '?')
			strcat(to, from);
	}

	/* skip authentication */
	if ((d = strchr(domain, '@')) != NULL)
		domain = d + 1;

	/* look for a port */
	if ((d = strrchr(domain, ':')) != NULL) {
		n = strspn(d + 1, "0123456789");
		if (*(d + n + 1) == 0) {
			s->port = atoi(d + 1);
			*d = 0;
		}
	}

	if (*domain == 0)
		return 0;

	strcpy(s->domain, domain);
	l = strlen(s->domain);

	if (strspn(s->domain, ".0123456789") == l) {
		/* may be an IPv4 address */
		unsigned char binaddr[sizeof(struct in_addr)];
		int changed = 0;

		if (inet_pton(AF_INET, s->domain, &binaddr) > 0) {
			struct hostent *hp = NULL;

			if (reverselookup) {
				if ((hp = gethostbyaddr(binaddr, sizeof(binaddr), AF_INET)) != NULL) {
					if (strlen(hp->h_name) < sizeof(s->domain)) {
						strcpy(s->domain, hp->h_name);
						changed = 0;
					}
				}
			}

			if (!changed)
				s->isAddress = 1;
		}
	} else if (s->domain[0] == '[' && s->domain[l - 1] == ']' &&
		   (strspn(s->domain + 1, ":0123456789abcdef") == l - 2)) {
		/* may be an IPv6 address */
		unsigned char binaddr[sizeof(struct in6_addr)];
		int changed = 0;

		s->domain[l - 1] = 0;

		if (inet_pton(AF_INET6, s->domain + 1, &binaddr) > 0) {
			struct hostent *hp = NULL;

			if (reverselookup) {
				if ((hp = gethostbyaddr(binaddr, sizeof(binaddr), AF_INET6)) != NULL) {
					if (strlen(hp->h_name) < sizeof(s->domain)) {
						strcpy(s->domain, hp->h_name);
						changed = 1;
					}
				}
			}

			if (!changed)
				s->isAddress = 1;
		}

		if (!changed)
			s->domain[l - 1] = ']';
	}

	/* strip trailing dot from domain */
	if ((d = s->domain + strlen(s->domain) - 1) >= s->domain)
		if (*d == '.')
			*d = 0;

	/* strip common host names like www.foo.com or web01.bar.org  */
	sdomain = s->domain;

	if ((domain[0] == 'w' && domain[1] == 'w' && domain[2] == 'w') ||
	    (domain[0] == 'w' && domain[1] == 'e' && domain[2] == 'b') ||
	    (domain[0] == 'f' && domain[1] == 't' && domain[2] == 'p')) {
		sdomain += 3;
		while (sdomain[0] >= '0' && sdomain[0] <= '9')
			sdomain++;

		if (sdomain[0] == '.')
			sdomain++;
		else
			sdomain = domain;
	}

	if (s->port > 0) {
		sprintf(s->furl, "%s:%d/%s", domain, s->port, pathcp);
		sprintf(s->surl, "%s:%d/%s", sdomain, s->port, pathcp);
	} else {
		sprintf(s->furl, "%s/%s", domain, pathcp);
		sprintf(s->surl, "%s/%s", sdomain, pathcp);
	}

	sgLogDebug("furl: %s domain: '%s' sdomain: '%s'", s->furl, s->domain, sdomain);

	sgFree(pathcp);

	return 1;
}

static int parseIdent(char *field, struct SquidInfo *s)
{
	char *p = NULL;

	HTUnEscape(field);

	if (strcmp(field, "-") != 0) {
		strcpy(s->ident, field);
		for (p = s->ident; *p != '\0'; p++) /* convert ident to lowercase chars */
			*p = tolower(*p);

		if (stripRealm && (p = strrchr(s->ident,'@'))) {
			if (realm) {
				if (strcmp(p, realm) == 0)
					*p = 0;
			} else {
				*p = 0;
			}
		}
	} else {
		s->ident[0] = '\0';
	}

	return 1;
}

/*
 * Parse an external acl helper line.
 *
 * Squid can be configured to pass various formats, we assume something
 * similar to the normal redirector format:
 *
 *   %URI %SRC %LOGIN
 *
 * For example:
 *   external_acl_type foo ttl=60 children=1 %URI %SRC %LOGIN /path/to/sg
 */
int parseAuthzLine(char *line, struct SquidInfo *s)
{
	char *field = NULL;

	sgLogDebug("got authz line %s", line);

	resetSquidInfo(s);

	/* get the URL and parse */
	if ((field = strtok(line, "\t ")) == NULL)
		return 0;

	HTUnEscape(field);
	if (!parseUrl(field, s))
		return 0;

	/* get the source address and parse */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	HTUnEscape(field);      /* just in case, IPs should not need escaping */
	strcpy(s->src, field);

	/* get the login and parse */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	if (!parseIdent(field,s))
		return 0;

	sgLogDebug("parsed authz line: furl='%s' domain='%s' surl='%s' src=%s ident='%s'",
		   s->furl, s->domain, s->surl, s->src, s->ident);

	return 1;
}

/*
 * Parse a redirector input line, format is:
 *
 *   URL ip-address/fqdn ident method
 *
 * for example
 *    http://www.example.com/page1.html 192.168.2.3/- andi GET
 */
int parseLine(char *line, struct SquidInfo *s)
{
	char *field = NULL;
	char *p = NULL;

	sgLogDebug("got redirector line %s", line);

	resetSquidInfo(s);

	/* get the URL and parse */
	if ((field = strtok(line, "\t ")) == NULL)
		return 0;

	HTUnEscape(field);
	if (!parseUrl(field, s))
		return 0;

	/* get the source address and parse */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	if ((p = strchr(field, '/')) != NULL) {
		*p = 0;
		strcpy(s->src, field);
		strcpy(s->srcDomain, p + 1);
		if (s->srcDomain[0] == '-' && s->srcDomain[1] == 0)
			s->srcDomain[0] = 0;
	} else {
		strcpy(s->src, field);
	}

	/* get the identity */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	if (!parseIdent(field,s))
		return 0;

	/* get the method */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	strcpy(s->method, field);
	if (s->method[0] == '\0')
		return 0;

	sgLogDebug("parsed redirector line: furl='%s' domain='%s' surl='%s' src=%s ident='%s'",
		   s->furl, s->domain, s->surl, s->src, s->ident);

	return 1;
}

char *substRedirect(const struct SquidInfo *req, const char *redirect, const char *srcClass, const char *destClass)
{
	char *result = NULL;
	const char *p = NULL;
	char *t;
	size_t rlen = strlen(redirect);

	//while ((p = strchr(p, '%')) != NULL) {
	for (p = strchr(redirect, '%'); p; p = strchr(p, '%')) {
		const char *np = p + 1;
		switch (*np) {
		case 'a':               // Source Address
			rlen += strlen(req->src);
			break;
		case 'i':               // Source User Ident
			rlen += strlen(req->ident);
			break;
		case 'n':               // Source Domain Name
			rlen += strlen(req->srcDomain);
			break;
		case 'p':               // The url path (??)
			break;
		case 'f':               // The url file (??)
			break;
		case 's':               // Target Class Matched
			rlen += (srcClass ? strlen(srcClass) : 1);
			break;
		case 't':               // Target Class Matched
			rlen += (destClass ? strlen(destClass) : 1);
			break;
		case 'u':               // Target URL
			rlen += strlen(req->orig);
			break;
		default:                // %% and unknown c
			rlen++;
			break;
		}
		p++;
	}

	result = sgMalloc(rlen + 1);
	*result = 0;
	t = result;

	for (p = redirect; *p; p++) {
		const char *np = p + 1;
		if (*p == '%') {
			switch (*np) {
			case 'a':               // Source Address
				t += sprintf(t, "%s", req->src);
				break;
			case 'i':               // Source User Ident
				t += sprintf(t, "%s", req->ident);
				break;
			case 'n':               // Source Domain Name
				t += sprintf(t, "%s", req->srcDomain);
				break;
			case 'p':               // The url path ??
				break;
			case 'f':               // The url file (??)
				break;
			case 's':               // Target Class Matched
				t += sprintf(t, "%s", (srcClass ? srcClass : "-"));
				break;
			case 't':               // Target Class Matched
				t += sprintf(t, "%s", (destClass ? destClass : "-"));
				break;
			case 'u':               // Target URL
				t += sprintf(t, "%s", req->orig);
				break;
			default:
				*t = *np;
				t++;
				break;
			}
			p++;
		} else {
			*t = *p;
			t++;
		}
	}

	*t = 0;
	return result;
}
