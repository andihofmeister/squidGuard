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

#define _GNU_SOURCE 1

#include <sys/types.h>
#include <regex.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include "sgSetting.h"
#include "sgRegex.h"
#include "sgMemory.h"
#include "sgLog.h"

#define REDIRECT_PERMANENT   "301:"
#define REDIRECT_TEMPORARILY "302:"

struct Regex {
	struct Regex *	next;
	char *		pattern;
	char *		substitute;
	regex_t *	compiled;
	int		error;
	int		flags;
	int		global;
	char *		httpcode;
};

struct RegexList {
	char *			name;
	struct RegexList *	next;

	struct Regex *		first;
	struct Regex *		last;
};

struct RegexList *firstRewrite = NULL;
struct RegexList *lastRewrite = NULL;

static struct Regex *newRegex(char *pattern, int flags)
{
	regex_t *compiled = sgMalloc(sizeof(regex_t));
	struct Regex *regexp = sgMalloc(sizeof(struct Regex));

	if (compiled == NULL || regexp == NULL) {
		sgFree(compiled);
		sgFree(regexp);
		return NULL;
	}

	regexp->error = 0;
	regexp->next = NULL;
	regexp->flags = flags;
	regexp->error = regcomp(compiled, pattern, flags);
	regexp->compiled = compiled;

	regexp->substitute = NULL;
	regexp->pattern = NULL; /* Remove ? */

	return regexp;
}

static void freeRegex(struct Regex *regexp)
{
	regfree(regexp->compiled);
	sgFree(regexp->compiled);
	sgFree(regexp->substitute);
	regexp->httpcode = NULL;                /* do not free, statically allocated */
	sgFree(regexp);
}

static struct RegexList *newRegexList(const char *name)
{
	struct RegexList *list = sgMalloc(sizeof(struct RegexList));

	if (list == NULL)
		return NULL;

	list->name = sgStrdup(name);
	list->next = NULL;
	list->first = NULL;
	list->last = NULL;

	return list;
}

static void freeRegexList(void *priv)
{
	struct RegexList *list = (struct RegexList *)priv;
	struct Regex *now = list->first;

	while (now) {
		struct Regex *next = now->next;
		freeRegex(now);
		now = next;
	}
	list->first = list->last = NULL;
	sgFree(list->name);
	sgFree(priv);
}

struct RegexList *newRewrite(const char *name)
{
	struct RegexList *result = newRegexList(name);

	if (result == NULL)
		return NULL;

	if (lastRewrite == NULL) {
		firstRewrite = result;
		lastRewrite = result;
	} else {
		lastRewrite->next = result;
		lastRewrite = result;
	}

	return result;
}

struct RegexList *findRewrite(const char *name)
{
	struct RegexList *now = firstRewrite;

	while (now) {
		if (strcmp(name, now->name) == 0)
			return now;
		now = now->next;
	}
	return NULL;
}

void addRewriteExpression(struct RegexList *list, const char *expr)
{
	struct Regex *regexp = NULL;
	int flags = REG_EXTENDED;
	int global = 0;

	char *pattern = NULL;
	char *subst = NULL;
	char *httpcode = NULL;

	const char *p = expr + 2;
	const char *s = p;

	while ((s = strchr(s, '@')) != NULL)
		if (*(s - 1) != '\\')
			break;

	pattern = strndup(p, s - p + 1);
	pattern[s - p] = 0;

	p = s++; s = p;
	while ((s = strchr(s, '@')) != NULL)
		if (*(s - 1) != '\\')
			break;

	subst = strndup(p, s - p + 1);
	subst[s - p] = 0;

	p = s++;

	while (*p != 0) {
		switch (*p) {
		case 'i':
			flags |= REG_ICASE;
			break;
		case 'g':
			global = 1;
			break;
		case 'r':
			httpcode = REDIRECT_TEMPORARILY;
			break;
		case 'R':
			httpcode = REDIRECT_PERMANENT;
			break;
		}
		p++;
	}

	if ((regexp = newRegex(pattern, flags)) == NULL)
		goto error_out;

	if (regexp->error) {
		char errbuf[256];
		regerror(regexp->error, regexp->compiled, errbuf, sizeof(errbuf));
		sgLogError("Error in regular expression %s", errbuf);
		goto error_out;
	}

	regexp->substitute = subst;
	regexp->httpcode = httpcode;
	regexp->global = global;

	if (list->last == NULL) {
		list->first = regexp;
		list->last = regexp;
	} else {
		list->last->next = regexp;
		list->last = regexp;
	}

	sgFree(pattern);

	return;

error_out:
	freeRegex(regexp);
	sgFree(pattern);
	sgFree(subst);
	return;
}

#define SUBMATCHES 10

static inline size_t patlen(regmatch_t *pat)
{
	if (pat->rm_so < 0)
		return 0;
	return pat->rm_eo - pat->rm_so;
}

static char *regexRewrite(struct Regex *regex, const char *url)
{
	regmatch_t pm[SUBMATCHES];
	char *p = NULL;
	char *t = NULL;
	char *result = NULL;
	size_t rlen = 0;

	if (regexec(regex->compiled, url, SUBMATCHES, pm, 0) != 0)
		return 0;

	/* first pass: determine the necessary length for our result. */
	for (p = regex->substitute; *p; p++) {
		char *np;
		switch (*p) {
		case '\\':
			np = p + 1;
			if (*np == '\\') {                      /* \\ -> \ */
				rlen++;
				p++;
			} else if (isdigit(*np)) {              /* \d -> sub-match d */
				int pi = *np - '0';
				rlen += patlen(&pm[pi]);
				p++;
			} else if (*np == '&') {                /* \& -> & */
				rlen++;
				p++;
			} else {
				rlen++;                         /* \c -> c */
				p++;
			}
			break;
		case '&':                                       /* & -> url */
			rlen += patlen(&pm[0]);
			break;
		default:
			rlen++;
		}
	}

	/* second pass: actually replace */
	result = sgMalloc(rlen + 1);
	t = result;

	for (p = regex->substitute; *p; p++) {
		char *np;
		switch (*p) {
		case '\\':
			np = p + 1;
			if (*np == '\\') {                      /* \\ -> \ */
				p++;
				*t = *p;
				t++;
			} else if (isdigit(*np)) {              /* \d -> sub-match d */
				int pi = *np - '0';
				size_t slen = patlen(&pm[pi]);
				strncpy(t, url + pm[pi].rm_so, slen);
				p++;
				t += slen;
			} else if (*np == '&') {                /* \& -> & */
				p++;
				*t = *p;
				t++;
			} else {                                /* \c -> c */
				p++;
				*t = *p;
				t++;
			}
			break;
		case '&':                                       /* & -> url */
			strncpy(t, url + pm[0].rm_so, patlen(&pm[0]));
			t += patlen(&pm[0]);
			break;
		default:
			*t = *p;
			t++;
		}
	}

	*t = 0;

	return result;;
}

char *applyRewrite(struct RegexList *list, const char *url)
{
	struct Regex *now = list->first;
	char *result = NULL;

	while (now) {
		if ((result = regexRewrite(now, url)) != NULL)
			break;

		now = now->next;
	}
	return result;;
}

void freeAllRewrites()
{
	struct RegexList *now = firstRewrite;

	while (now) {
		struct RegexList *next = now->next;
		freeRegexList(now);
		now = next;
	}

	firstRewrite = lastRewrite = NULL;
}

static int regexMatch(void *priv, const struct SquidInfo *req)
{
	struct Regex *rp;
	static char errbuf[256];
	int error;

	sgLogDebug("checking regex from %s", ((struct RegexList *)priv)->name);

	for (rp = ((struct RegexList *)priv)->first; rp != NULL; rp = rp->next) {
		error = regexec(rp->compiled, req->furl, 0, 0, 0);
		if (error != 0 && error != REG_NOMATCH) {
			regerror(error, rp->compiled, errbuf, sizeof(errbuf));
			sgLogError("Error in regex while matching %-60.60s  %d %s", req->furl, error, errbuf);
		}
		if (error == 0) { /* match */
			sgLogDebug("  match");
			return 1;
		}
	}
	sgLogDebug("  no match");
	return 0;
}

struct DestMatch *newDestExpressionListMatch(char *name, char *exprlist, char *chcase)
{
	struct DestMatch *result = NULL;
	struct RegexList *list = NULL;
	const char *dbhome = getSetting("dbhome");
	char *filename = NULL;
	FILE *fp;

	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;

	if (exprlist == NULL) {
		size_t len = strlen("/dest/") + strlen(name) + strlen("/domainlist") +
			     strlen(dbhome) + strlen("/") + 4;
		filename = sgMalloc(len);
		snprintf(filename, len, "%s/dest/%s/domainlist", dbhome, name);
	} else {
		if (exprlist[0] == '/') {
			filename = sgStrdup(exprlist);
		} else {
			size_t len = strlen(dbhome) + strlen("/") + strlen(exprlist) + 4;
			filename = sgMalloc(len);
			snprintf(filename, len, "%s/%s", dbhome, exprlist);
		}
	}

	sgLogDebug("init expressionlist %s", filename);

	if ((result = sgNewDestMatch(regexMatch, freeRegexList)) == NULL) {
		sgFree(filename);
		return NULL;
	}

	if ((list = newRegexList(filename)) == NULL) {
		freeDestMatch(result);
		sgFree(filename);
		return NULL;
	}

	result->priv = list;

	if ((fp = fopen(filename, "r")) != NULL) {
		char buf[MAX_BUF], errbuf[256];
		int lineno = 0;
		int flags = REG_EXTENDED;

		while (fgets(buf, sizeof(buf), fp) != NULL) {
			struct Regex *regexp = NULL;
			char *p = strchr(buf, '\n');
			lineno++;
			if (p != NULL && p != buf) {
				if (*(p - 1) == '\r') /* removing ^M  */
					p--;
				*p = '\0';
			}

			if ((regexp = newRegex(buf, flags)) == NULL)
				continue;

			if (regexp->error) {
				regerror(regexp->error, regexp->compiled, errbuf, sizeof(errbuf));
				sgLogError("%s:%d %s", filename, lineno, errbuf);
				freeRegex(regexp);
				continue;
			}

			if (list->last == NULL) {
				list->first = regexp;
				list->last = regexp;
			} else {
				list->last->next = regexp;
				list->last = regexp;
			}
		}
		fclose(fp);
	} else {
		sgLogError("%s: %s", filename, strerror(errno));
		sgFree(filename);
		freeDestMatch(result);
		return NULL;
	}

	sgFree(filename);
	return result;
}
