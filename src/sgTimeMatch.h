#ifndef SG_TIME_MATCH
#define SG_TIME_MATCH 1

#include <time.h>

enum TimeScope {
	T_WITHIN  = 0,
	T_OUTSIDE = 1,
};

struct TimeMatch {
	char *				name;
	time_t				nextCheck;
	int				lastResult;
	struct TimeMatch *		next;
	struct TimeMatchElement *	firstElement;
	struct TimeMatchElement *	lastElement;
};

struct TimeMatch;
struct TimeMatchElement;

struct TimeMatch *newTimeMatch(const char *name);
void freeAllTimeMatches();
struct TimeMatch *findTimeMatch(const char *name);

struct TimeMatchElement *addWeeklyElement(struct TimeMatch *match, const char *days);
struct TimeMatchElement *addWeekdayElement(struct TimeMatch *match, const char *days);
struct TimeMatchElement *dupWeeklyElement(struct TimeMatch *match, struct TimeMatchElement *orig);

struct TimeMatchElement *addDateElement(struct TimeMatch *match, const char *date, const char *date_to);
struct TimeMatchElement *addCronDateElement(struct TimeMatch *match, const char *date);
struct TimeMatchElement *dupDateElement(struct TimeMatch *match, struct TimeMatchElement *orig);

void setTimeValues(struct TimeMatchElement *match, const char *from, const char *to);

int matchTime(struct TimeMatch *match);

#endif
