#ifndef SG_SOURCELIST_H
#define SG_SOURCELIST_H 1

#include "sgRequest.h"
#include "patricia/patricia.h"
#include <time.h>

struct SourceList {
	struct SourceList *	next;
	char *			name;

	time_t			positiveCacheTime;
	time_t			negativeCacheTime;

	struct RequestLog *	log;

	struct TimeMatch *	time;
	int			timeOutside;

	struct SourceMatch *	first;
	struct SourceMatch *	last;

	int			staticUsers;
	int			staticIps;

	int			needUserCache;
	int			needIPCache;

	struct sgDb *		userCache;
	patricia_tree_t *	ipCache;
	patricia_tree_t *	ip6Cache;
};

struct SourceList *findSourceList(const char *name);
struct SourceList *newSourceList(const char *name);
struct SourceList *lastSourceList(void);

void freeSourceList(struct SourceList *list);
void freeAllSourceLists();

void addSourceListMatch(struct SourceList *list, struct SourceMatch *dest);

void addUserPermanently(struct SourceList *list, const char *ident);
void addIpPermanently(struct SourceList *list, const char *ip);

void addSourceListTime(struct SourceList *list, const char *tname, int invert);
void addSourceListLog(struct SourceList *list, struct RequestLog *log);

int matchSourceList(struct SourceList *list, const struct SquidInfo *info);
#endif
