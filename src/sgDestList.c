#include <string.h>

#include "sgMatch.h"
#include "sgDestList.h"
#include "sgTimeMatch.h"
#include "sgMemory.h"
#include "sgLog.h"
#include "sgRegex.h"

static struct DestList *firstDest = NULL;
static struct DestList *lastDest = NULL;

struct DestList *findDestList(const char *name)
{
	struct DestList *now;

	for (now = firstDest; now != NULL; now = now->next)
		if (strcmp(now->name, name) == 0)
			return now;

	return NULL;
}

struct DestList *newDestList(const char *name)
{
	struct DestList *result = sgMalloc(sizeof(struct DestList));

	if (result == NULL)
		return NULL;

	result->name = sgStrdup(name);
	result->time = NULL;
	result->timeOutside = 0;
	result->first = NULL;
	result->last = NULL;
	result->next = NULL;
	result->rewrite = NULL;

	if (lastDest == NULL) {
		firstDest = result;
		lastDest = result;
	} else {
		lastDest->next = result;
		lastDest = result;
	}

	return result;
}

static void freeDestList(struct DestList *list)
{
	struct DestMatch *now = list->first;

	while (now) {
		struct DestMatch *next = now->next;
		freeDestMatch(now);
		now = next;
	}

	sgFree(list->redirect);
	sgFree(list->name);
	sgFree(list);
}

void freeAllDestLists()
{
	struct DestList *now = firstDest;

	while (now != NULL) {
		struct DestList *next = now->next;
		freeDestList(now);
		now = next;
	}

	firstDest = lastDest = NULL;
}

void addDestListMatch(struct DestList *list, struct DestMatch *dest)
{
	if (dest == NULL)
		return;

	if (list == NULL)
		list = lastDest;

	if (list->first == NULL) {
		list->first = dest;
		list->last = dest;
	} else {
		list->last->next = dest;
		list->last = dest;
	}
}

void addDestListTime(struct DestList *list, const char *tname, int invert)
{
	if ((list->time = findTimeMatch(tname)) == NULL)
		sgLogError("time match %s is not defined", tname);

	list->timeOutside = invert;
}

void addDestListRewrite(struct DestList *list, const char *rewrite)
{
	if (list->rewrite) {
		sgLogError("dest list %s already has a rewrite", list->name);
		return;
	}

	if ((list->rewrite = findRewrite(rewrite)) == NULL)
		sgLogError("rewrite '%s' not defined before destination %s", rewrite, list->name);
}

void addDestListRedirect(struct DestList *list, const char *redirect)
{
	if (list->redirect) {
		sgLogError("destination list %s already has a redirect", list->name);
		return;
	}

	list->redirect = sgStrdup(redirect);
}

void addDestListLog(struct DestList *list, struct RequestLog *log)
{
	if (list->log) {
		sgLogError("request list %s already has a log", list->name);
		return;
	}

	list->log = log;
}

/*
 * Returns true if any element in the list matches.
 */
int matchDestList(struct DestList *list, const struct SquidInfo *info)
{
	struct DestMatch *now;
	int result = 0;

	sgLogDebug("Checking destination list %s", list->name);

	if (list->time) {
		result = matchTime(list->time);
		if (list->timeOutside) {
			if (result) {
				sgLogDebug("destination list not outside time %s", list->time->name);
				return 0;
			}
		} else {
			if (!result) {
				sgLogDebug("destination list not within time %s", list->time->name);
				return 0;
			}
		}
	}

	for (now = list->first; now != NULL; now = now->next)
		if ((result = now->match(now->priv, info)) != 0)
			return result;

	return 0;
}
