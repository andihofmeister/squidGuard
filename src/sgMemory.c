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
#include "sgMemory.h"
#include "sgEx.h"


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

void sgFreeAllLists()
{
#define FREE_LIST(type, head, func) \
	{ \
		struct type *next; \
		while (head != NULL) { \
			next = head->next; \
			func(head); \
			head = next; \
		} \
	}

	/* settings linked list */
	FREE_LIST(Setting, Setting, sgFreeSetting)
	lastSetting = NULL;
	Setting = NULL;

	/* sources */
	FREE_LIST(Source, Source, sgFreeSource)
	lastSource = NULL;
	Source = NULL;
	lastActiveSource = NULL;

	/* dests */
	FREE_LIST(Destination, Dest, sgFreeDestination)
	lastDest = NULL;
	Dest = NULL;

	/* rewrites */
	FREE_LIST(sgRewrite, Rewrite, sgFreeRewrite)
	lastRewrite = NULL;
	Rewrite = NULL;
	lastRewriteRegExec = NULL;

	/* time structures */
	FREE_LIST(Time, Time, sgFreeTime)
	lastTime = NULL;
	Time = NULL;
	lastTimeElement = NULL;
	TimeElement = NULL;

	/* log file stats */
	FREE_LIST(LogFileStat, LogFileStat, sgFreeLogFileStat)
	lastLogFileStat = NULL;
	LogFileStat = NULL;

	/* access control lists */
	FREE_LIST(Acl, Acl, sgFreeAcl)
	lastAcl = NULL;
	defaultAcl = NULL;
	Acl = NULL;
	lastAclDest = NULL;


	/* single variables */
	free(globalLogDir);
	globalLogDir = NULL;

	sgFree(TimeElementsEvents);
	TimeElementsEvents = NULL;
}

void sgFreeDestination(struct Destination *dest)
{
	sgFree(dest->name);
	sgFree(dest->domainlist);
	sgFree(dest->domainlistDb);
	sgFree(dest->urllist);
	sgFree(dest->urllistDb);
	sgFree(dest->expressionlist);
	sgFree(dest->redirect);
	sgFree(dest->logfile);
	/*struct Time *time;*/          /* not dynamically allocated */
	/*struct sgRewrite *rewrite;*/

	FREE_LIST(sgRegExp, dest->regExp, sgFreePatternBuffer)

	/* and finally, the object itself */
	sgFree(dest);
}

void sgFreeSource(struct Source *src)
{
	int i;

	sgFree(src->name);
	sgFree(src->domainDb);
	sgFree(src->userDb);
	sgFree(src->logfile);
	/*struct Time *time;*/          /* not dynamically allocated */

#ifdef HAVE_LIBLDAP
	sgFree(src->ipDb);
	for (i = 0; i < src->ldapuserurlcount; i++)
		sgFree(src->ldapuserurls[i]);
	sgFree(src->ldapuserurls);
	for (i = 0; i < src->ldapipurlcount; i++)
		sgFree(src->ldapipurls[i]);
	sgFree(src->ldapipurls);
#endif

	FREE_LIST(Ip, src->ip, sgFreeIp)

	/* and finally, the object itself */
	sgFree(src);
}

void sgFreeIp(struct Ip *ip)
{
	sgFree(ip->str);
	sgFree(ip);
}

void sgFreeSetting(struct Setting *set)
{
	free(set->name);
	free(set->value);
	sgFree(set);
}

void sgFreeTime(struct Time *t)
{
	free(t->name);
	FREE_LIST(TimeElement, t->element, sgFree)
	sgFree(t);
}

void sgFreeRewrite(struct sgRewrite *rew)
{
	sgFree(rew->name);
	sgFree(rew->logfile);
	FREE_LIST(sgRegExp, rew->rewrite, sgFreePatternBuffer)
	sgFree(rew);
}

void sgFreeAcl(struct Acl *acl)
{
	sgFree(acl->name);
	sgFree(acl->redirect);
	sgFree(acl->logfile);
	sgFree(acl->tag);

	FREE_LIST(AclDest, acl->pass, sgFreeAclDest)

	/*struct Source *source;*/      /* not dynamically allocated */
	/*struct sgRewrite *rewrite;*/
	/*struct Time *time;*/

	sgFree(acl);
}

void sgFreeAclDest(struct AclDest *ad)
{
	sgFree(ad->name);
	/*struct Destination *dest;*/   /* not dynamically allocated */

	sgFree(ad);
}

void sgFreeLogFileStat(struct LogFileStat *lfs)
{
	if (lfs->name != NULL) sgFree(lfs->name);
	sgFree(lfs);
}

