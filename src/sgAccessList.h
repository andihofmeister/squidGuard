#ifndef SG_ACL_H
#define SG_ACL_H 1

#include "sgSourceList.h"
#include "sgDestList.h"
#include "sgTimeMatch.h"
#include "sgRegex.h"
#include "sgRequestLog.h"

enum AccessResults {
	ACCESS_UNDEFINED,
	ACCESS_GRANTED,
	ACCESS_DENIED
};

struct AccessList {
	struct AccessList *	next;

	char *			name;
	char *			tag;
	char *			redirect;

	int			terminal;
	int			allow;

	struct RequestLog *	log;

	struct TimeMatch *	time;
	int			timeOutside;

	struct SourceList *	source;

	struct DestCheck *	firstDest;
	struct DestCheck *	lastDest;

	struct RegexList *	rewrite;
};

struct AccessList *newAccessList(const char *name);
void freeAllAccessLists(void);

struct AccessList *getFirstAccessList(void);

void addDestinationAccessCheck(struct AccessList *list, int inverted, const char *destListName);
void addAccessListTime(struct AccessList *list, const char *tname, int invert);
void addAccessListRedirect(struct AccessList *list, const char *redirect);
void addAccessListRewrite(struct AccessList *list, const char *tname);
void addAccessListLog(struct AccessList *list, struct RequestLog *log);

void setDefaultRedirect(const char *redirect);
void freeDefaultRedirect(void);

enum AccessResults checkAccess(struct AccessList *list, const struct SquidInfo *request, char **redirect);

#endif
