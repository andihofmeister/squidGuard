/*
 * Group handling for squidGuard
 *
 * Copyright (C) 2005 Coreworks GbR, Freiburg i. Br., Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to:
 *     Free Software Foundation, Inc.
 *     59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: 030-group.diff,v 1.4 2006/01/18 15:17:03 gritter Exp $
 */

#include "sg.h"
#include <pwd.h>
#include <grp.h>

char *krbRealm = NULL;

int groupDebug;

#define dprintf(...)    if (groupDebug) sgLogError(__VA_ARGS__)
#define dputs(s)        if (groupDebug) sgLogError("%s", s)

static struct node {
	struct node *	n_next;
	char *		n_name;
	struct node **	n_table;
	time_t		n_time;
	gid_t		n_gid;
} **groups;
#define PGROUP  997
#define PUSERS  4999

time_t groupttl = 600;

static char *
sstrdup(const char *cp)
{
	char *np;

	np = sgMalloc(strlen(cp) + 1);
	strcpy(np, cp);
	return np;
}

static struct node *
listadd(struct node *lh, const char *name)
{
	struct node *lp, *lq = NULL;

	lp = sgMalloc(sizeof *lp);
	lp->n_name = sstrdup(name);
	if (lh != NULL) {
		for (lq = lh; lq->n_next != NULL; lq = lq->n_next) ;
		lq->n_next = lp;
	} else {
		lh = lp;
	}
	return lh;
}

static struct node *
listget(struct node *lp, const char *name)
{
	while (lp)
		if (strcmp(lp->n_name, name) == 0)
			break;
	return lp;
}

static void
listfree(struct node *lp)
{
	struct node *lq;

	while (lp != NULL) {
		lq = lp->n_next;
		sgFree(lp->n_name);
		sgFree(lp);
		lp = lq;
	}
}

static unsigned
pjw(const char *cp)
{
	unsigned h = 0, g;

	cp--;
	while (*++cp) {
		h = (h << 4 & 0xffffffff) + (*cp & 0377);
		if ((g = h & 0xf0000000) != 0) {
			h = h ^ g >> 24;
			h = h ^ g;
		}
	}
	return h;
}

static void
hfree(struct node **table, unsigned hprime)
{
	unsigned i;

	if (table) {
		for (i = 0; i < hprime; i++)
			listfree(table[i]);
		sgFree(table);
	}
}

static struct node *
hlook(struct node **table, unsigned hprime, const char *name, struct node *new)
{
	struct node *np, *nq = NULL;
	unsigned h;

	if (table == NULL)
		return NULL;
	np = table[h = pjw(name) % hprime];
	while (np != NULL) {
		if (np->n_name && strcmp(np->n_name, name) == 0)
			break;
		nq = np;
		np = np->n_next;
	}
	if (new) {
		if (np != NULL) {
			new->n_next = np->n_next;
			sgFree(np->n_name);
			sgFree(np);
			if (nq)
				nq->n_next = new;
			else
				table[h] = new;
		} else {
			new->n_next = table[h];
			table[h] = new;
		}
		np = new;
	}
	return np;
}

static void
adduser(struct node **table, const char *name)
{
	struct node *new;

	new = sgMalloc(sizeof *new);
	new->n_name = sstrdup(name);
	hlook(table, PUSERS, name, new);
}

static void
retrievegroup(const char *name)
{
	struct node *new;
	struct group *grp;
	int i;

	new = sgMalloc(sizeof *new);
	new->n_name = sstrdup(name);
	time(&new->n_time);
	dprintf("group debug: retrieving group \"%s\": ", name);
	if ((grp = getgrnam(name)) != NULL) {
		new->n_table = sgCalloc(PUSERS, sizeof *new->n_table);
		new->n_gid = grp->gr_gid;
		for (i = 0; grp->gr_mem[i] != NULL; i++)
			adduser(new->n_table, grp->gr_mem[i]);
		dprintf("group debug: %d members", i);
	} else {
		new->n_gid = (gid_t)-1;
	}
	if (groups == NULL)
		groups = sgCalloc(PGROUP, sizeof *groups);
	hlook(groups, PGROUP, name, new);
}

void
sgSourceGroup(char *user)
{
	extern struct Source *lastSource;
	struct Source *sp;

	sp = lastSource;
	sp->grouplist = listadd(sp->grouplist, user);
}

int
unhexlify(char c)
{
	char ret = c;

	if (c >= '0' && c <= '9')
		ret -= '0';
	else if (c >= 'A' && c <= 'F')
		ret -= 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		ret -= 'a' + 10;
	else
		ret = -1;

	return ret;
}

void
unescape(char *s)
{
	char *tmp = s;
	int offset = 0;
	int len = strlen(s);

	int i;

	for (i = 0; i < len; ) {
		if (s[i] == '%') {
			tmp[offset] = unhexlify(s[i + 1]) << 4 | unhexlify(s[i + 2]);
			offset++;
			i += 3;
		} else {
			tmp[offset] = s[i];
			offset++;
			i++;
		}
	}

	s[offset] = '\0';
}

void
stripRealm(char *name, char *realm)
{
	char *first;

	if (!realm)
		return;

	first = strchr(name, '@');
	while (first) {
		if (!strcasecmp((char *)(first + 1), realm)) {
			first[0] = 0;
			return;
		}
		first = strchr(first + 1, '@');
	}
}

int
groupmember(void *grouplist, char *user, const char *source)
{
	struct passwd *pwd;
	struct node *gp, *np;
	time_t now;

	if (grouplist == NULL)
		return 0;

	unescape(user);

	stripRealm(user, krbRealm);

	dprintf("group debug: CHECK: if \"%s\" is in groups "
		"for source \"%s\"",
		user, source);
	time(&now);
	for (gp = grouplist; gp != NULL; gp = gp->n_next) {
		dprintf("group debug: check if user \"%s\" is in group \"%s\"",
			user, gp->n_name);
		if ((np = hlook(groups, PGROUP, gp->n_name, NULL)) == NULL ||
		    np->n_time + groupttl <= now) {
			if (np) {
				hfree(np->n_table, PUSERS);
				np->n_table = NULL;
			}
			retrievegroup(gp->n_name);
			np = hlook(groups, PGROUP, gp->n_name, NULL);
		}
		if (np != NULL &&
		    hlook(np->n_table, PUSERS, user, NULL) != NULL) {
			dputs("group debug: YES: found as supplementary or "
			      "cached primary group");
			return 1;
		}
		dputs("group debug: no supplementary or cache group match");
	}
	dprintf("group debug: retrieving user \"%s\"\n", user);
	if ((pwd = getpwnam(user)) != NULL) {
		for (gp = grouplist; gp != NULL; gp = gp->n_next) {
			dprintf("group debug: whether \"%s\" has "
				"primary group \"%s\": ",
				user, gp->n_name);
			if ((np = hlook(groups, PGROUP, gp->n_name, NULL))
			    != NULL &&
			    np->n_gid != (gid_t)-1 &&
			    np->n_gid == pwd->pw_gid) {
				adduser(np->n_table, user);
				dputs("group debug: YES: found as "
				      "primary group");
				return 1;
			}
		}
		dputs("group debug: no primary group match");
	} else {
		dprintf("group debug: getpwnam(%s) failed", user);
	}
	dprintf("group debug: NO: user \"%s\" not a member of groups "
		"for source \"%s\"",
		user, source);
	return 0;
}
