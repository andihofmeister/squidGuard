
#include <string.h>

#include "sgSourceList.h"
#include "sgDestList.h"
#include "sgAccessList.h"
#include "sgMemory.h"
#include "sgLog.h"

static struct AccessList *firstAccessList = NULL;
static struct AccessList *lastAccessList = NULL;

static char *defaultRedirect = NULL;

struct DestCheck {
	struct DestCheck *	next;
	struct DestList *	list;
	int			inverted;
};

void setDefaultRedirect(const char *redirect)
{
	if (defaultRedirect) {
		sgLogError("default redirect already set");
		return;
	}

	defaultRedirect = sgStrdup(redirect);
}

void freeDefaultRedirect()
{
	sgFree(defaultRedirect);
	defaultRedirect = NULL;
}

static struct DestCheck *newDestCheck(const char *name)
{
	struct DestCheck *result = sgMalloc(sizeof(struct DestCheck));

	if (result == NULL)
		return NULL;

	if ((result->list = findDestList(name)) == NULL) {
		sgLogError("destination list '%s' undefined, skip", name);
		sgFree(result);
		return NULL;
	}

	result->inverted = 0;
	result->next = NULL;

	return result;
}

static void freeDestCheck(struct DestCheck *check)
{
	sgFree(check);
}

struct AccessList *newAccessList(const char *name)
{
	struct AccessList *result = sgMalloc(sizeof(struct AccessList));
	struct SourceList *source = findSourceList(name);

	if (result == NULL)
		return NULL;

	result->name = sgStrdup(name);
	result->next = NULL;

	result->source = source;

	result->firstDest = NULL;
	result->lastDest = NULL;

	result->log = NULL;
	result->redirect = NULL;
	result->rewrite = NULL;

	if (lastAccessList == NULL) {
		firstAccessList = result;
		lastAccessList = result;
	} else {
		lastAccessList->next = result;
		lastAccessList = result;
	}

	return result;
}

static void freeAccessList(struct AccessList *list)
{
	struct DestCheck *dnow = list->firstDest;

	while (dnow != NULL) {
		struct DestCheck *dnext = dnow->next;
		freeDestCheck(dnow);
		dnow = dnext;
	}

	sgFree(list->redirect);
	sgFree(list->name);
	sgFree(list);
}

void freeAllAccessLists()
{
	struct AccessList *now = firstAccessList;

	while (now) {
		struct AccessList *next = now->next;
		freeAccessList(now);
		now = next;
	}

	firstAccessList = lastAccessList = NULL;
}

void addDestinationAccessCheck(struct AccessList *list, int inverted, const char *destListName)
{
	struct DestCheck *dest = newDestCheck(destListName);

	if (dest == NULL)
		return;

	dest->inverted = inverted;

	if (strcmp(destListName, "none") == 0 ) {
		/* special hack for "none" which is an inverted "any" match */
		dest->inverted = 1;
	}

	if (list->lastDest == NULL) {
		list->firstDest = dest;
		list->lastDest = dest;
	} else {
		list->lastDest->next = dest;
		list->lastDest = dest;
	}
}

struct AccessList *getFirstAccessList()
{
	return firstAccessList;
}

void addAccessListTime(struct AccessList *list, const char *tname, int invert)
{
	if ((list->time = findTimeMatch(tname)) == NULL)
		sgLogError("time match %s is not defined", tname);

	list->timeOutside = invert;
}

void addAccessListRedirect(struct AccessList *list, const char *redirect)
{
	if (list->redirect) {
		sgLogError("access list %s already has a redirect", list->name);
		return;
	}

	list->redirect = sgStrdup(redirect);
}

void addAccessListRewrite(struct AccessList *list, const char *rewrite)
{
	if (list->rewrite) {
		sgLogError("access list %s already has a rewrite", list->name);
		return;
	}

	if ((list->rewrite = findRewrite(rewrite)) == NULL)
		sgLogError("rewrite '%s' not defined before acl %s", rewrite, list->name);
}

void addAccessListLog(struct AccessList *list, struct RequestLog *log)
{
	if (list->log) {
		sgLogError("access list %s already has a log", list->name);
		return;
	}

	list->log = log;
}

/*
 * Check if the ACL 'list' grants access for 'request'.
 *
 * An ACL applies if
 *
 *  * the acl time matches, otherwise the access is undefined.
 *  * the source matches, otherwise the access is undefined.
 *
 * Only afther these checks succeded, destination checks are applied.
 *
 * Any matching destination check terminates further destination checks, the
 * inversion just determines if the destination check allows or denies access.
 *
 * Rewrites or redirects happen based on the access decission, but only if the
 * caller (the main loop) did pass a char ** where to store the the rewrite
 * result. It should not do that in "authz" mode.
 *
 * If the access rule _denied_ access, rewrite/redirects are checked in this
 * order unless a rewrite has been found:
 *
 *  * rewrite from the matching destination block
 *  * redirect from the matching destinaton block
 *  * rewrite from the the ACL block
 *  * redirect from the ACL block
 *  * global rewrite
 *
 * If the access rule _granted_ access, redirects can still happen if the matching
 * destination block had a rewrite or redirect statement AND the access decission is
 * terminal (caused by a 'pass' statement instead of 'next' in the ACL block).
 *
 */
enum AccessResults checkAccess(struct AccessList *list, const struct SquidInfo *request, char **rewrite)
{
	int found = 0;
	struct DestList *matchingDest = NULL;
	char *redirect = NULL;

	sgLogDebug("==> checking ACL %s", list->name);

	if (list->time) {
		int result = matchTime(list->time);
		if (list->timeOutside) {
			if (result) {
				sgLogDebug("<== access list not outside time %s", list->time->name);
				return ACCESS_UNDEFINED;
			}
		} else {
			if (!result) {
				sgLogDebug("<== access list not within time %s", list->time->name);
				return ACCESS_UNDEFINED;
			}
		}
	}

	if (list->source) {
		if (!matchSourceList(list->source, request))
			return ACCESS_UNDEFINED;
	}

	if (list->firstDest) {
		struct DestCheck *check;

		for (check = list->firstDest; check; check = check->next) {
			int match = matchDestList(check->list, request);
			if (match) {
				if (check->inverted)
					found = 0;
				else
					found = 1;

				matchingDest = check->list;
				sgLogDebug("list %s matched, found set to %d", matchingDest->name, found);
				break;
			}
		}
	}

	if (found) {
		if (list->terminal) {
			struct RequestLog *requestLog = NULL;

			if (rewrite) {
				if (!redirect && matchingDest->rewrite)
					redirect = applyRewrite(matchingDest->rewrite, request->furl);

				if (!redirect && matchingDest->redirect)
					redirect = substRedirect(request, matchingDest->redirect,
								 list->name, matchingDest->name);

				if (redirect)
					*rewrite = redirect;
			}

			if (list->source && list->source->log)
				requestLog = list->source->log;
			else if (matchingDest && matchingDest->log)
				requestLog = matchingDest->log;
			else
				requestLog = defaultRequestLog;

			if (requestLog) {
				doRequestLog(requestLog,
					     request,
					     list->name,
					     (matchingDest ? matchingDest->name : NULL),
					     (rewrite ? *rewrite : NULL),
					     ACCESS_GRANTED);
			}

			sgLogDebug("<== Access finaly granted with%s redirect%s%s",
				   (redirect ? "" : "out"), (redirect ? " to" : ""), (redirect ? redirect : ""));
			return ACCESS_GRANTED;
		} else {
			sgLogDebug("<== no final access decission");
			return ACCESS_UNDEFINED;
		}
	}

	if (rewrite) {
		if (list->rewrite)
			redirect = applyRewrite(list->rewrite, request->furl);

		if (!redirect && list->redirect)
			redirect = substRedirect(request, list->redirect, list->name,
						 (matchingDest ? matchingDest->name : "-"));

		if (!redirect && matchingDest && matchingDest->rewrite)
			redirect = applyRewrite(matchingDest->rewrite, request->furl);

		if (!redirect && matchingDest && matchingDest->redirect)
			redirect = substRedirect(request, matchingDest->redirect, list->name, matchingDest->name);

		if (!redirect && defaultRedirect)
			redirect = substRedirect(request, defaultRedirect, list->name,
						 (matchingDest ? matchingDest->name : "-"));
		if (redirect)
			*rewrite = redirect;
	}

	{
		struct RequestLog *requestLog = NULL;

		if (list->log)
			requestLog = list->log;
		else if (list->source && list->source->log)
			requestLog = list->source->log;
		else if (matchingDest && matchingDest->log)
			requestLog = matchingDest->log;
		else
			requestLog = defaultRequestLog;

		if (requestLog) {
			doRequestLog(requestLog,
				     request,
				     list->name,
				     (matchingDest ? matchingDest->name : NULL),
				     (rewrite ? *rewrite : NULL),
				     ACCESS_DENIED);
		}
	}

	sgLogDebug("<== Access finaly denied with%s redirect%s%s",
		   (redirect ? "" : "out"), (redirect ? " to " : ""), (redirect ? redirect : ""));

	return ACCESS_DENIED;
}
