#ifndef SG_DESTLIST_H
#define SG_DESTLIST_H 1

#include "sgRequest.h"
#include "sgRegex.h"
#include "sgRequestLog.h"

struct DestList {
	struct DestList *	next;
	char *			name;

	struct RequestLog *	log;

	struct TimeMatch *	time;
	int			timeOutside;

	struct RegexList *	rewrite;
	char *			redirect;

	struct DestMatch *	first;
	struct DestMatch *	last;

	int			lastSerialMatched;
	int			lastSerialResult;
};

struct DestList *findDestList(const char *name);
struct DestList *newDestList(const char *name);
void freeAllDestLists(void);

void addDestListMatch(struct DestList *list, struct DestMatch *dest);
void addDestListTime(struct DestList *list, const char *tname, int invert);
void addDestListRewrite(struct DestList *list, const char *rewrite);
void addDestListRedirect(struct DestList *list, const char *redirect);
void addDestListLog(struct DestList *list, struct RequestLog *log);

int matchDestList(struct DestList *list, const struct SquidInfo *info);

#endif
