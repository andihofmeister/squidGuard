/*
  By accepting this notice, you agree to be bound by the following
  agreements:

  This software product, squidGuard, is copyrighted (C) 2007 by
  Christine Kronberg, Shalla Secure Services, with all rights reserved.

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License (version 2) as
  published by the Free Software Foundation.  It is distributed in the
  hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the GNU General Public License (GPL) for more details.

  You should have received a copy of the GNU General Public License
  (GPL) along with this program.
*/

#include "sg.h"
#include "sgEx.h"

void sgFreeAllLists()
{
#define FREE_LIST(type, head, func) \
       { \
               struct type *next; \
               while(head != NULL) { \
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

#if __STDC__
void sgFreeDestination(struct Destination *dest)
#else
void sgFreeDestination(dest)
       struct Destination *dest;
#endif
{
       if(dest->name != NULL)          sgFree(dest->name);
       if(dest->domainlist != NULL)    sgFree(dest->domainlist);
       if(dest->domainlistDb != NULL)  sgFree(dest->domainlistDb);
       if(dest->urllist != NULL)       sgFree(dest->urllist);
       if(dest->urllistDb != NULL)     sgFree(dest->urllistDb);
       if(dest->expressionlist != NULL)sgFree(dest->expressionlist);
       if(dest->redirect != NULL)      sgFree(dest->redirect);
       if(dest->logfile != NULL)       sgFree(dest->logfile);
       /*struct Time *time;*/          /* not dynamically allocated */
       /*struct sgRewrite *rewrite;*/

       FREE_LIST(sgRegExp, dest->regExp, sgFreePatternBuffer)

       /* and finally, the object itself */
       sgFree(dest);
}

#if __STDC__
void sgFreeSource(struct Source *src)
#else
void sgFreeSource(src)
       struct Source *src;
#endif
{
       int i;

       if(src->name != NULL)           sgFree(src->name);
       if(src->domainDb != NULL)       sgFree(src->domainDb);
       if(src->userDb != NULL)         sgFree(src->userDb);
       if(src->logfile != NULL)        sgFree(src->logfile);
       /*struct Time *time;*/          /* not dynamically allocated */

#ifdef HAVE_LIBLDAP
       for(i = 0; i < src->ldapurlcount; i++) {
               sgFree(src->ldapurls[i]);
       }
       sgFree(src->ldapurls);
#endif

       FREE_LIST(Ip, src->ip, sgFreeIp)

       /* and finally, the object itself */
       sgFree(src);
}

#if __STDC__
void sgFreeIp(struct Ip *ip)
#else
void sgFreeIp(ip)
       struct Ip *ip;
#endif
{
       if(ip->str != NULL)             sgFree(ip->str);
       sgFree(ip);
}

#if __STDC__
void sgFreeSetting(struct Setting *set)
#else
void sgFreeSetting(set)
       struct Setting *set;
#endif
{
       if(set->name != NULL)           free(set->name);
       if(set->value != NULL)          free(set->value);
       sgFree(set);
}

#if __STDC__
void sgFreeTime(struct Time *t)
#else
void sgFreeTime(t)
       struct Time *t;
#endif
{
       if(t->name != NULL)             free(t->name);
       FREE_LIST(TimeElement, t->element, sgFree)
       sgFree(t);
}

#if __STDC__
void sgFreeRewrite(struct sgRewrite *rew)
#else
void sgFreeRewrite(rew)
       struct sgRewrite *rew;
#endif
{
       if(rew->name != NULL)           sgFree(rew->name);
       if(rew->logfile != NULL)        sgFree(rew->logfile);
       FREE_LIST(sgRegExp, rew->rewrite, sgFreePatternBuffer)
       sgFree(rew);
}

#if __STDC__
void sgFreeAcl(struct Acl *acl)
#else
void sgFreeAcl(acl)
       struct Acl *acl;
#endif
{
       if(acl->name != NULL)           sgFree(acl->name);
       if(acl->redirect != NULL)       sgFree(acl->redirect);
       if(acl->logfile != NULL)        sgFree(acl->logfile);

       FREE_LIST(AclDest, acl->pass, sgFreeAclDest)

       /*struct Source *source;*/      /* not dynamically allocated */
       /*struct sgRewrite *rewrite;*/
       /*struct Time *time;*/

       sgFree(acl);
}

#if __STDC__
void sgFreeAclDest(struct AclDest *ad)
#else
void sgFreeAclDest(ad)
       struct AclDest *ad;
#endif
{
       if(ad->name != NULL)            sgFree(ad->name);
       /*struct Destination *dest;*/   /* not dynamically allocated */

       sgFree(ad);
}

#if __STDC__
void sgFreeLogFileStat(struct LogFileStat *lfs)
#else
void sgFreeLogFileStat(lfs)
       struct LogFileStat *lfs;
#endif
{
       if(lfs->name != NULL)           sgFree(lfs->name);
       sgFree(lfs);
}


