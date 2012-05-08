

#ifndef SG_TIME_H
#define SG_TIME_H 1

enum TimeScope {
	T_WITHIN,
	T_OUTSIDE
};

struct TimeElement {
	char			wday;
	int			from;
	int			to;
	int			y;
	int			m;
	int			d;
	time_t			fromdate;
	time_t			todate;
	struct TimeElement *	next;
};

struct Time {
	char *			name;
	int			active;
	struct TimeElement *	element;
	struct Time *		next;
};


void sgTime(char *);
struct Time *sgTimeFindName(char *);
void sgTimeElementInit();
void sgTimeElementSortEvents();
void sgTimeElementAdd(char *, char);
void sgTimeElementEnd();
int sgTimeNextEvent();
void sgTimeElementClone();

#endif
