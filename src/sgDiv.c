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

#include "sg.h"
#include "sgEx.h"

/* #define METEST 8; */

void sgHandlerSigHUP(int signal)
{
	sig_hup = 1;
}

void sgReloadConfig()
{
	struct LogFileStat *sg;
	struct Source *src;
	struct Destination *dest;

	sig_hup = 0;
	sgLogWarn("WARN: Received sigHUP, reloaded configuration");
	for (sg = LogFileStat; sg != NULL; sg = sg->next) { /* closing logfiles */
		if (sg->fd == stderr || sg->fd == stdout)
			continue;
		fclose(sg->fd);
	}
	for (src = Source; src != NULL; src = src->next) {
		if (src->domainDb != NULL && src->domainDb->dbp != NULL)
			(void)src->domainDb->dbp->close(src->domainDb->dbp, 0);
		if (src->userDb != NULL && src->userDb->dbp != NULL)
			(void)src->userDb->dbp->close(src->userDb->dbp, 0);
	}
	for (dest = Dest; dest != NULL; dest = dest->next) {
		if (dest->domainlistDb != NULL && dest->domainlistDb->dbp != NULL)
			(void)dest->domainlistDb->dbp->close(dest->domainlistDb->dbp, 0);
		if (dest->urllistDb != NULL && dest->urllistDb->dbp != NULL)
			(void)dest->urllistDb->dbp->close(dest->urllistDb->dbp, 0);
	}
	sgFreeAllLists();
	execve(*globalArgv, globalArgv, globalEnvp);
	fprintf(stderr, "error execve: %d\n", errno);
	exit(1);
}

void sgAlarm(int signal)
{
	sig_alrm = 1;
	sgTimeNextEvent();
}

/*
 * parsers the squidline:
 * URL ip-address/fqdn ident method
 */

int parseLine(char *line, struct SquidInfo *s)
{
	char *p, *d = NULL, *a = NULL, *e = NULL, *o, *field;
	int i = 0;
	char c;
	int report_once = 1;
	int trailingdot = 0;
	size_t strsz;
	int ndx = 0;

	field = strtok(line, "\t ");
	/*field holds each fetched url*/
	/* Let's first decode the url and then test it. Fixes bug2. */
	HTUnEscape(field);

	if (field == NULL)
		return 0;
	strcpy(s->orig, field);
	/* Now convert url to lowercase chars */
	for (p = field; *p != '\0'; p++)
		*p = tolower(*p);
	s->url[0] = s->protocol[0] = s->domain[0] = s->src[0] = s->ident[0] =
									s->method[0] = s->srcDomain[0] = s->surl[0] = '\0';
	s->dot = 0;
	s->port = 0;
	p = strstr(field, "://");
	/* sgLogDebug("DEBUG P2 = %s", p); */
	if (p == NULL) { /* no protocol, defaults to http */
		strcpy(s->protocol, "unknown");
		p = field;
	} else {
		strncpy(s->protocol, field, p - field);
		*(s->protocol + (p - field)) = '\0';
		p += 3; /* JMC -- 3 == strlen("://") */
		/* Now p only holds the pure URI */
		/* Fix for multiple slash vulnerability (bug1). */
		/* Check if there are still two or more slashes in sequence which must not happen */
		strsz = strlen(p);

		/* loop thru the string 'p' until the char '?' is hit or the "end" is hit */
		while ('?' != p[ndx] && '\0' != p[ndx]) {
			/* in case this is a '://' skip over it, but try to not read past EOS */
			if (3 <= strsz - ndx) {
				if (':' == p[ndx] && '/' == p[ndx + 1] && '/' == p[ndx + 2] && '\0' != p[ndx + 3])
					ndx += 3; /* 3 == strlen("://"); */
			}

			/* if this char and the next char are slashes,
			 *           then shift the rest of the string left one char */
			if ('/' == p[ndx] && '/' == p[ndx + 1]) {
				size_t sz = strlen(p + ndx + 1);
				strncpy(p + ndx, p + ndx + 1, sz);
				p[ndx + sz] = '\0';
				if (1 == report_once) {
					sgLogWarn("WARN: Possible bypass attempt. Found multiple slashes where only one is expected: %s", s->orig);
						report_once--;
				}
			} else if ('.' == p[ndx] && '/' == p[ndx + 1] && trailingdot == 0) {
				/* If the domain has trailing dot, remove (problem found with squid 3.0 stable1-5) */
				/* if this char is a dot and the next char is a slash, then shift the rest of the string left one char */
				/* We do this only the first time it is encountered. */
				trailingdot++;
				size_t sz = strlen(p + ndx + 1);
				strncpy(p + ndx, p + ndx + 1, sz);
				p[ndx + sz] = '\0';
				sgLogWarn("WARN: Possible bypass attempt. Found a trailing dot in the domain name: %s", s->orig);
			} else {
				/* increment the string indexer */
				assert(ndx < strlen(p));
				ndx++;
			}
		}
	}

	i = 0;
	d = strchr(p, '/'); /* find domain end */
	/* Check for the single URIs (d) */
	/* sgLogDebug("DEBUG: URL: %s", d); */
	e = d;
	a = strchr(p, '@'); /* find auth  */
	if (a != NULL && (a < d || d == NULL))
		p = a + 1;
	a = strchr(p, ':'); /* find port */;
	if (a != NULL && (a < d || d == NULL)) {
		o = a + strspn(a + 1, "0123456789") + 1;
		c = *o;
		*o = '\0';
		s->port = atoi(a + 1);
		*o = c;
		e = a;
	}
	o = p;
	strcpy(s->furl, p);
	if (p[0] == 'w' || p[0] == 'f') {
		if ((p[0] == 'w' && p[1] == 'w' && p[2] == 'w') ||
		    (p[0] == 'w' && p[1] == 'e' && p[2] == 'b') ||
		    (p[0] == 'f' && p[1] == 't' && p[2] == 'p')) {
			p += 3;
			while (p[0] >= '0' && p[0] <= '9')
				p++;
			if (p[0] != '.')
				p = o;  /* not a hostname */
			else
				p++;
		}
	}
	if (e == NULL) {
		strcpy(s->domain, o);
		strcpy(s->surl, p);
	} else {
		strncpy(s->domain, o, e - o);
		strcpy(s->surl, p);
		*(s->domain + (e - o)) = '\0';
		*(s->surl + (e - p)) = '\0';
	}
	//strcpy(s->surl,s->domain);
	if (strspn(s->domain, ".0123456789") == strlen(s->domain))
		s->dot = 1;
	if (d != NULL)
		strcat(s->surl, d);
	s->strippedurl = s->surl;

	while ((p = strtok(NULL, " \t\n")) != NULL) {
		switch (i) {
		case 0: /* src */
			o = strchr(p, '/');
			if (o != NULL) {
				strncpy(s->src, p, o - p);
				strcpy(s->srcDomain, o + 1);
				s->src[o - p] = '\0';
				if (*s->srcDomain == '-')
					s->srcDomain[0] = '\0';
			} else {
				strcpy(s->src, p);
			}
			break;
		case 1: /* ident */
			if (strcmp(p, "-")) {
				strcpy(s->ident, p);
				for (p = s->ident; *p != '\0'; p++) /* convert ident to lowercase chars */
					*p = tolower(*p);
			} else {
				s->ident[0] = '\0';
			}
			break;
		case 2: /* method */
			strcpy(s->method, p);
			break;
		}
		i++;
	}
	if (s->domain[0] == '\0')
/*    sgLogDebug("DEBUG: Domain is NULL: %s", s->orig); */
		return 0;
	if (s->method[0] == '\0')
/*    sgLogDebug("DEBUG: Method is NULL: %s", s->orig); */
		return 0;
	return 1;
}

char *sgStripUrl(char *url)
{
	static char newurl[MAX_BUF];
	char *p, *d = NULL, *a = NULL, *e = NULL;
	p = url;
	d = strchr(p, '/');     /* find domain end */
	e = d;
	a = strchr(p, '@');     /* find auth  */
	if (a != NULL && (a < d || d == NULL))
		p = a + 1;
	a = strchr(p, ':'); /* find port */;
	if (a != NULL && (a < d || d == NULL))
		e = a;
	if (e == NULL) {
		strcpy(newurl, p);
	} else {
		strncpy(newurl, p, e - p);
		*(newurl + (e - p)) = '\0';
	}
	if (d != NULL)
		strcat(newurl, d);
	return newurl;
}

/*
 * returns a pointer to the domain part of a fully-qualified  hostname
 * so www.abc.xyz.dom/index.html -> xyz.dom/index.html
 */

char *sgSkipHostPart(char *domain)
{
	char *p = domain, *d1 = NULL, *d2 = NULL, *path = NULL;
	if ((path = (char *)strchr(p, '/')) == NULL)
		path = domain;
	while ((p = (char *)strchr(p, '.')) != NULL) {
		if (p > path && path != domain)
			break;
		d2 = d1;
		d1 = p;
		p++;
	}
	if (d2 != NULL)
		return d2 + 1;
	return domain;
}

void *sgMalloc(size_t elsize)
{
	void *p;
	if ((p = (void *)malloc(elsize)) == NULL) {
		sgLogFatal("FATAL: %s: %s", progname, strerror(ENOMEM));
		exit(1);
	}
	return (void *)p;
}

void *sgCalloc(size_t nelem, size_t elsize)
{
	void *p;
	if ((p = (void *)calloc(nelem, elsize)) == NULL) {
		sgLogFatal("FATAL: %s: %s", progname, strerror(ENOMEM));
		exit(1);
	}
	return (void *)p;
}


void *sgRealloc(void *ptr, size_t elsize)
{
	void *p;
	if ((p = (void *)realloc(ptr, elsize)) == NULL) {
		sgLogFatal("FATAL: %s: %s", progname, strerror(ENOMEM));
		exit(1);
	}
	return (void *)p;
}

void _sgFree(void *ptr)
{
	free(ptr);
}


/*
 *
 * checks the vality of an dotted address.
 *
 */

ulong *sgConvDot(char *dot)
{
	static unsigned long ipaddr = 0;
	int octet;
	char *s = dot, *t;
	int shift = 24;
	ipaddr = 0;
	while (*s) {
		t = s;
		if (!isdigit(*t))
			return NULL;
		while (isdigit(*t))
			++t;
		if (*t == '.')
			*t++ = 0;
		else if (*t)
			return NULL;
		if (shift < 0)
			return NULL;
		octet = atoi(s);
		if (octet < 0 || octet > 255)
			return NULL;
		ipaddr |= octet << shift;
		s = t;
		shift -= 8;
	}
	return &ipaddr;
}


/*
 * Reverses cmp of strings
 */

int sgStrRcmp(char *a, char *b)
{
	char *a1 = (char *)strchr(a, '\0');
	char *b1 = (char *)strchr(b, '\0');
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

int sgStrRncmp(char *a, char *b, int blen)
{
	char *a1 = (char *)strchr(a, '\0');
	char *b1 = (char *)strchr(b, '\0');
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


int sgDomStrRcmp(char *p1, char *p2)
{
	char *p11 = (char *)strchr(p1, '\0');
	char *p22 = (char *)strchr(p2, '\0');
	for (; p11 >= p1 && p22 >= p2 && *p11 == *p22; p11--, p22--) ;
	if (p11 < p1 && p22 < p2)
		return 0;
	if (p22 < p2)
		return -*p11;
	if (p11 < p1 && *p22 == '.')
		return 0;
	return *p11 - *p22;
}

/*
 *
 * Regexp functions
 *
 */

struct sgRegExp *sgNewPatternBuffer(char *pattern, int flags)
{
	regex_t *compiled = sgMalloc(sizeof(regex_t));
	struct sgRegExp *regexp;
	regexp = sgMalloc(sizeof(struct sgRegExp));
	regexp->pattern = sgMalloc(strlen(pattern) + 1);
	strcpy(regexp->pattern, pattern);
	regexp->error = 0;
	regexp->next = NULL;
	regexp->flags = flags;
	regexp->error = regcomp(compiled, pattern, flags);
	regexp->compiled = compiled;
	return regexp;
}

/*
 * Deletes the buffer memory, so save the next pointer first before
 * calling this function.
 */
void sgFreePatternBuffer(struct sgRegExp *regexp)
{
	sgFree(regexp->pattern);
	sgFree(regexp->compiled);
	sgFree(regexp);
}

char *sgRegExpSubst(struct sgRegExp *regexp, char *pattern)
{
	struct sgRegExp *re;
	regmatch_t pm[10];
	static char newstring[MAX_BUF];
	char *result = NULL, *p;
	int substlen;
	*newstring = '\0';
	for (re = regexp; re != NULL; re = re->next) {
		if (regexec(re->compiled, pattern, sizeof(pm) / sizeof(pm[0]), pm, 0) != 0) {
			result = NULL;
		} else {
			substlen = strlen(re->substitute);
			if (re->httpcode != NULL)
				strcpy(newstring, re->httpcode);
			else
				*newstring = '\0';
			p = newstring;
			do {
				if ((p - newstring) + pm[0].rm_so >= MAX_BUF)
					break;
				p = strncat(newstring, pattern, pm[0].rm_so);
				{
					char *p_cur;
					char *p_next;

					for (p_next = p_cur = re->substitute;
					     p_next < (re->substitute + substlen);
					     p_next++) {
						if (*p_next == '\\') {
							if (p_cur < p_next) {
								if (((p - newstring) + (p_next - p_cur)) >= MAX_BUF)
									goto err;
								p = strncat(newstring, p_cur, p_next - p_cur);
							}
							p_next++;
							if (p_next < (re->substitute + substlen)
							    && '0' <= *p_next && *p_next <= '9') {
								int i = *p_next - '0';
								if ((p - newstring) + (pm[i].rm_eo - pm[i].rm_so) >= MAX_BUF)
									goto err;
								p = strncat(newstring, pattern + pm[i].rm_so, pm[i].rm_eo - pm[i].rm_so);
							} else {
								if ((p - newstring + 1) >= MAX_BUF)
									goto err;
								p = strncat(newstring, p_next, 1);
							}
							p_cur = p_next + 1;
						} else if (*p_next == '&') {
							if (p_cur < p_next) {
								if (((p - newstring) + (p_next - p_cur)) >= MAX_BUF)
									goto err;
								p = strncat(newstring, p_cur, p_next - p_cur);
							}
							if (((p - newstring) + (pm[0].rm_eo - pm[0].rm_so)) >= MAX_BUF)
								goto err;
							p = strncat(newstring, pattern + pm[0].rm_so, pm[0].rm_eo - pm[0].rm_so);
							p_cur = p_next + 1;
						}
					}
					if (p_cur < p_next) {
						if (((p - newstring) + (p_next - p_cur)) >= MAX_BUF)
							goto err;
						p = strncat(newstring, p_cur, p_next - p_cur);
					}
				}
				pattern = pattern + pm[0].rm_eo;
			} while (regexec(re->compiled, pattern, sizeof(pm) / sizeof(pm[0]), pm, REG_NOTBOL) == 0 && re->global);
			if ((p - newstring) + strlen(pattern) <= MAX_BUF)
				p = strcat(newstring, pattern);
			result = newstring;
			break;
		}
	}
err:
	return result;
}

/*
 *
 *
 *
 */

char *sgParseRedirect(char *redirect, struct SquidInfo *req, struct Acl *acl, struct AclDest *aclpass)
{
	static char buf[MAX_BUF + MAX_BUF];
	char *p = redirect, *q = NULL, *t = NULL;
	struct Source *s = lastActiveSource;
	*buf = '\0';
	if (aclpass == NULL)
		aclpass = defaultAcl->pass;
	while ((p = strchr(p, '%')) != NULL) {
		if (q == NULL) {
			strncpy(buf, redirect, p - redirect);
			buf[p - redirect] = '\0';
		} else {
			strncat(buf, q, p - q);
		}
		if (p == NULL)
			break;
		switch (*(p + 1)) {
		case 'a': /* Source Address */
			strcat(buf, req->src);
			p++;
			break;
		case 'i': /* Source User Ident */
			if (!strcmp(req->ident, "-"))
				strcat(buf, "unknown");
			else
				strcat(buf, req->ident);
			p++;
			break;
		case 'q': /* userquota info */
			if (s != NULL && s->userquota.seconds != 0 && strcmp(req->ident, "-")) {
				struct UserInfo *userquota;
				if (defined(s->userDb, req->ident, (char **)&userquota) == 1) {
					char qbuf[150];
					sprintf(qbuf, "%d-%d-%d-%d-%d-%d", s->userquota.renew, s->userquota.seconds, userquota->status, userquota->time, userquota->last, userquota->consumed);
					strcat(buf, qbuf);
				} else {
					strcat(buf, "noquota");
				}
			} else {
				strcat(buf, "noquota");
			}
		case 'n': /* Source Domain Name */
			if (!strcmp(req->srcDomain, "-"))
				strcat(buf, "unknown");
			else
				strcat(buf, req->srcDomain);
			p++;
			break;
		case 'p': /* The url path */
			if ((t = strstr(req->orig, "//")) != NULL) {
				t += 2;
				if ((t = strchr(t, '/')) != NULL)
					strcat(buf, ++t);
			}
			p++;
			break;
		case 'f': /* The url file */
			if ((t = strrchr(req->orig, '/')) != NULL) {
				t++;
				strcat(buf, t);
			}
			p++;
			break;
		case 's': /* Source Class Matched */
			if (acl->source == NULL || acl->source->name == NULL)
				strcat(buf, "default");
			else
				strcat(buf, acl->source->name);
			p++;
			break;
		case 't': /* Target Class Matched */
			if (aclpass == NULL) {
				strcat(buf, "unknown");
			} else if (aclpass->name == NULL) {
				if (aclpass->type == ACL_TYPE_INADDR)
					strcat(buf, "in-addr");
				else if (aclpass->type == ACL_TYPE_TERMINATOR)
					strcat(buf, "none");
				else
					strcat(buf, "unknown");
			} else {
				strcat(buf, aclpass->name);
			}
			p++;
			break;
		case 'u': /* Requested URL */
			strncat(buf, req->orig, 2048);
			p++;
			break;
		default:
			strcat(buf, "%")
			;
		}
		p++;
		q = p;
	}
	if (buf[0] == '\0')
		q = redirect;
	else
		q = buf;
	return q;
}

void sgEmergency()
{
	char buf[MAX_BUF];
	extern char *globalCreateDb;
	extern int passthrough; /* from main.c */

	if (globalCreateDb == NULL) {
		if (passthrough == 1) {
			sgLogWarn("WARN: Not going into emergency mode because -P was used");
			fprintf(stderr, "              ****************\n");
			fprintf(stderr, "FAILURE! Check your log file for problems with the database files!\n");
			fprintf(stderr, "              ****************\n");
			exit(4);
		}
	}
	sgLogError("ERROR: Going into emergency mode");
	while (fgets(buf, MAX_BUF, stdin) != NULL) {
		puts("");
		fflush(stdout);
	}
	sgLogError("ERROR: Ending emergency mode, stdin empty");
	exit(-1);
}


/*
 * converts yyyy.mm.ddTHH:MM:SS to seconds since EPOC
 */

time_t iso2sec(char *date)
{
	struct tm *t;
	int y, m, d, H, M, S;
	t = sgMalloc(sizeof(struct tm));
	sscanf(date, "%4d%*[.-]%2d%*[.-]%2d%*[T]%2d%*[:-]%2d%*[:-]%2d",
	       &y, &m, &d, &H, &M, &S);
	m--;
	y = y - 1900;
	if (y < 0 || m < 0 || m > 11 || d < 1 || d > 31 || H < 0 || H > 23
	    || M < 0 || M > 59 || S < 0 || S > 59)
		return (time_t)-1;
	t->tm_year = y;
	t->tm_mon = m;
	t->tm_mday = d;
	t->tm_hour = H;
	t->tm_min = M;
	t->tm_sec = S;
	return (time_t)mktime(t);
}

/*
 * converts yyyy.mm.dd to seconds since EPOC
 */

time_t date2sec(char *date)
{
	struct tm *t;
	int y, m, d;
	t = sgMalloc(sizeof(struct tm));
	sscanf(date, "%4d%*[.-]%2d%*[.-]%2d", &y, &m, &d);
	m--;
	y = y - 1900;
	if (y < 0 || m < 0 || m > 11 || d < 1 || d > 31)
		return (time_t)-1;
	t->tm_year = y;
	t->tm_mon = m;
	t->tm_mday = d;
	return (time_t)mktime(t);
}

char *niso(time_t t)
{
	static char buf[20];
	time_t tp;
	struct tm *lc;
	if (t == 0)
		tp = time(NULL) + globalDebugTimeDelta;
	else
		tp = t;
	lc = localtime(&tp);
	sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", lc->tm_year + 1900, lc->tm_mon + 1,
		lc->tm_mday, lc->tm_hour, lc->tm_min, lc->tm_sec);
	return buf;
}

struct UserInfo *setuserinfo()
{
	static struct UserInfo uq;

	uq.status = 0;
	uq.time = 0;
	uq.consumed = 0;
	uq.last = 0;
#ifdef HAVE_LIBLDAP
	uq.ldapuser = 0;
	uq.found = 0;
	uq.cachetime = 0;
#endif
	return &uq;
}

#ifdef HAVE_LIBLDAP
struct IpInfo *setipinfo()
{
	static struct IpInfo uq;

	uq.status = 0;
	uq.time = 0;
	uq.consumed = 0;
	uq.last = 0;
	uq.ldapip = 0;
	uq.found = 0;
	uq.cachetime = 0;
	return &uq;
}
#endif
