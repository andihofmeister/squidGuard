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
#include "HTEscape.h"

#include <netdb.h>
#include <arpa/inet.h>

/* #define METEST 8; */
int reverselookup = 0;

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

static void resetSquidInfo(struct SquidInfo *s) {
	s->protocol[0]  = '\0';
	s->domain[0]    = '\0';
	s->dot          = 0;
	s->url[0]       = '\0';
	s->orig[0]      = '\0';
	s->surl[0]      = '\0';
	s->furl[0]      = '\0';
	s->strippedurl  = s->surl;
	s->port         = 0;
	s->src[0]       = '\0';
	s->srcDomain[0] = '\0';
	s->ident[0]     = '\0';
	s->method[0]    = '\0';
}

static int parseUrl(char * url, struct SquidInfo *s) {

	char * p = NULL;
	char * d = NULL;
	size_t l = 0;
	size_t n = 0;
	char * domain  = NULL;
	char * sdomain = NULL;

	char pathcp[MAX_BUF];

	memset(pathcp,0,sizeof(pathcp));

	strcpy(s->orig, url);

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
	if ((d = strchr(p,'/')) != NULL) {
		p = d + 1;
		*d = 0;
	} else {
		p = NULL;
	}

	/* p now is either NULL or points to the first char in the path part*/
	if (p != NULL) {
		char * to   = pathcp;
		char * from = p;

		/* skip leading slashes */
		while( *from == '/' )
			from ++;

		while ( *from != 0 && *from != '?' ) {
			/* skip double slashes */
			if (*from == '/' && *(from+1) == '/') {
				from ++;
				continue;
			}
			*to = *from;
			to ++; from ++;
		}

		/* keep the query part when present */
		if ( *from == '?' )
			strcat(to,from);
	}

	/* skip authentication */
	if ((d = strchr(domain, '@')) != NULL) {
		domain = d + 1;
	}

	/* look for a port */
	if ((d = strrchr(domain,':')) != NULL) {
		n = strspn(d + 1, "0123456789");
		if ( *(d + n + 1) == 0 ) {
			s->port = atoi(d + 1);
			*d = 0;
		}
	}

	if (*domain == 0)
		return 0;

	strcpy(s->domain, domain);
	l = strlen(s->domain);

	if (strspn(s->domain, ".0123456789") == l ) {
		/* may be an IPv4 address */
		unsigned char binaddr[sizeof(struct in_addr)];
		int changed = 0;

		if ( inet_pton(AF_INET, s->domain, &binaddr) > 0 ) {
			struct hostent * hp = NULL;

			if (reverselookup) {
				if ((hp = gethostbyaddr( binaddr, sizeof(binaddr), AF_INET )) != NULL) {
					if (strlen(hp->h_name) < MAX_BUF) {
						strcpy(s->domain, hp->h_name);
						changed = 0;
					}
				}
			}

			if (!changed)
				s->dot = 1;
		}
	} else if (s->domain[0] == '[' && s->domain[l- 1] == ']' &&
		   (strspn(s->domain + 1, ":0123456789abcdef") == l - 2)) {
		/* may be an IPv6 address */
		unsigned char binaddr[sizeof(struct in6_addr)];
		int changed = 0;

		s->domain[l-1] = 0;

		if ( inet_pton(AF_INET6, s->domain + 1, &binaddr) > 0 ) {
			struct hostent * hp = NULL;

			if (reverselookup) {
				if ((hp = gethostbyaddr( binaddr, sizeof(binaddr), AF_INET6 )) != NULL) {
					if (strlen(hp->h_name) < MAX_BUF) {
						strcpy(s->domain, hp->h_name);
						changed = 1;
					}
				}
			}

			if (!changed)
				s->dot = 1;
		}

		if (!changed)
			s->domain[l-1] = ']';
	}

	/* strip trailing dot from domain */
	if ((d = s->domain + strlen(s->domain) - 1) >= s->domain) {
		if (*d == '.')
			*d = 0;
	}

	/* strip common host names like www.foo.com or web01.bar.org  */
	sdomain = s->domain;

	if ((domain[0] == 'w' &&  domain[1] == 'w' && domain[2] == 'w') ||
	    (domain[0] == 'w' &&  domain[1] == 'e' && domain[2] == 'b') ||
	    (domain[0] == 'f' &&  domain[1] == 't' && domain[2] == 'p'))
	{
		sdomain += 3;
		while (sdomain[0] >= '0' && sdomain[0] <= '9')
			sdomain ++;

		if (sdomain[0] == '.')
			sdomain ++;
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
	char * field = NULL;

	resetSquidInfo(s);

	/* get the URL and parse */
	if ((field = strtok(line, "\t ")) == NULL)
		return 0;

	HTUnEscape(field);
	if (!parseUrl(field,s)) {
		return 0;
	}

	/* get the source address and parse */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	HTUnEscape(field);	/* just in case, IPs should not need escaping */
	strcpy(s->src, field);

	/* get the login and parse */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	HTUnEscape(field);

	strcpy(s->ident, field);

	for (field = s->ident; *field != '\0'; field++) /* convert ident to lowercase chars */
		*field = tolower(*field);

	sgLogDebug( "got authz helper line: furl='%s' domain='%s' surl='%s' src=%s ident='%s'\n",
			s->furl, s->domain, s->surl, s->src, s->ident );

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
	char * field = NULL;
	char * p = NULL;

	resetSquidInfo(s);

	/* get the URL and parse */
	if ((field = strtok(line, "\t ")) == NULL)
		return 0;

	HTUnEscape(field);
	if (!parseUrl(field,s)) {
		return 0;
	}

	/* get the source address and parse */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	if ((p = strchr(field, '/')) != NULL) {
		*p = 0;
		strcpy(s->src, field);
		strcpy(s->srcDomain,p + 1);
		if (s->srcDomain[0] == '-' && s->srcDomain[1] == 0)
			s->srcDomain[0] = 0;

	} else {
		strcpy(s->src, field);
	}

	/* get the identity */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	if (strcmp(field, "-")) {
		strcpy(s->ident, field);
		for (p = s->ident; *p != '\0'; p++) /* convert ident to lowercase chars */
			*p = tolower(*p);
	} else {
		s->ident[0] = '\0';
	}

	/* get the method */
	if ((field = strtok(NULL, " \t\n")) == NULL)
		return 0;

	strcpy(s->method, field);
	if (s->method[0] == '\0')
		return 0;

	sgLogDebug( "got line: furl='%s' domain='%s' surl='%s' src=%s ident='%s'\n",
			s->furl, s->domain, s->surl, s->src, s->ident );

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
	memset(p,0,elsize);
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
					sprintf(qbuf, "%d-%ld-%d-%ld-%ld-%d",
					        s->userquota.renew,
					        s->userquota.seconds,
					        userquota->status,
					        userquota->time,
					        userquota->last,
					        userquota->consumed);
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
