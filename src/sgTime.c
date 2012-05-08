
#include "sg.h"
#include "sgEx.h"
#include "sgTime.h"
#include "sgLog.h"
#include "sgMemory.h"

static int time_switch = 0;
static int date_switch = 0;

static int numTimeElements = 0;
int *TimeElementsEvents;

struct Time *lastTime = NULL;
struct Time *Time = NULL;                      /* linked list, Calloc */

static void sgTimeSetAcl();
static int sgTimeCheck(struct tm *, time_t);

/*
 * Time functions
 */

void sgTime(char *name)
{
	struct Time *t;
	if (Time != NULL) {
		if ((struct Time *)sgTimeFindName(name) != NULL)
			sgLogFatal("%s: time %s is defined in configfile",
				   progname, name);
	} else {
		numTimeElements = 0;
	}
	t = sgMalloc(sizeof(struct Time));
	t->name = strdup(name);
	t->element = NULL;
	t->active = 1;
	TimeElement = NULL;
	lastTimeElement = NULL;
	if (Time == NULL) {
		Time = t;
		lastTime = t;
	} else {
		lastTime->next = t;
		lastTime = t;
	}
}

void sgTimeElementInit()
{
	struct TimeElement *te;

	te = sgMalloc(sizeof(struct TimeElement));
	numTimeElements++;
	if (lastTime->element == NULL)
		lastTime->element = te;
	if (lastTimeElement != NULL)
		lastTimeElement->next = te;
	lastTimeElement = te;
}

void sgTimeElementEnd()
{
	time_switch = 0;
	date_switch = 0;
	if (lastTimeElement->fromdate != 0) {
		if (lastTimeElement->todate == 0)
			lastTimeElement->todate = lastTimeElement->fromdate + 86399;
		else
			lastTimeElement->todate = lastTimeElement->todate + 86399;
	}
	if (lastTimeElement->from == 0 && lastTimeElement->to == 0)
		lastTimeElement->to = 1439;  /* set time to 23:59 */
}

void sgTimeElementAdd(char *element, char type)
{
	struct TimeElement *te;
	char *p;
	char wday = 0;
	int h, m, Y, M = 0, D = -1;
	time_t sec;
	te = lastTimeElement;
	switch (type) {
	case T_WEEKDAY:
		p = strtok(element, " \t,");
		do {
			if (*p == '*')
				wday = 127;
			else if (!strncmp(p, "sun", 3))
				wday = wday | 0x01;
			else if (!strncmp(p, "mon", 3))
				wday = wday | 0x02;
			else if (!strncmp(p, "tue", 3))
				wday = wday | 0x04;
			else if (!strncmp(p, "wed", 3))
				wday = wday | 0x08;
			else if (!strncmp(p, "thu", 3))
				wday = wday | 0x10;
			else if (!strncmp(p, "fri", 3))
				wday = wday | 0x20;
			else if (!strncmp(p, "sat", 3))
				wday = wday | 0x40;
			p = strtok(NULL, " \t,");
		} while (p != NULL);
		te->wday = wday;
		break;
	case T_TVAL:
		sscanf(element, "%d:%d", &h, &m);
		if ((h < 0 && h > 24) && (m < 0 && m > 59))
			sgLogFatal("%s: FATAL: time formaterror", progname);
		if (time_switch == 0) {
			time_switch++;
			te->from = (h * 60) + m;
		} else {
			time_switch = 0;
			te->to = (h * 60) + m;
		}
		break;
	case T_DVAL:
		sec = date2sec(element);
		if (sec == -1)
			sgLogFatal("%s: FATAL: date formaterror", lineno);
		if (date_switch == 0) {
			date_switch++;
			te->fromdate = sec;
		} else {
			date_switch = 0;
			te->todate = sec;
		}
		break;
	case T_DVALCRON:
		p = strtok(element, "-.");
		Y = atoi(p);
		if (*p == '*')
			Y = -1;
		else
			Y = atoi(p);
		while ((p = strtok(NULL, "-.")) != NULL) {
			if (*p == '*') {
				if (M == 0)
					M = -1;
				else
					D = -1;
			} else
			if (M == 0) {
				M = atoi(p);
			} else {
				D = atoi(p);
			}
		}
		te->y = Y; te->m = M; te->d = D;
		break;
	case T_WEEKLY:
		p = element;
		while (*p != '\0') {
			switch (*p) {
			case 'S':
			case 's':
				wday = wday | 0x01;
				break;
			case 'M':
			case 'm':
				wday = wday | 0x02;
				break;
			case 'T':
			case 't':
				wday = wday | 0x04;
				break;
			case 'W':
			case 'w':
				wday = wday | 0x08;
				break;
			case 'H':
			case 'h':
				wday = wday | 0x10;
				break;
			case 'F':
			case 'f':
				wday = wday | 0x20;
				break;
			case 'A':
			case 'a':
				wday = wday | 0x40;
				break;
			default:
				sgLogFatal("%s: FATAL: weekday formaterror", progname );
				break;
			}
			p++;
		}
		te->wday = wday;
		break;
	}
}


struct Time *sgTimeFindName(char *name)
{
	struct Time *p;
	for (p = Time; p != NULL; p = p->next)
		if (!strcmp(name, p->name))
			return p;
	return NULL;
}

static int sgTimeCmp(const int *a, const int *b)
{
	return *a - *b;
}

void sgTimeElementSortEvents()
{
	struct Time *p;
	struct TimeElement *te;
	int i = 0, j;
	int *t;

	if (Time != NULL) {
		TimeElementsEvents = sgCalloc(numTimeElements * 2, sizeof(int));
		t = sgCalloc(numTimeElements * 2, sizeof(int));
		for (p = Time; p != NULL; p = p->next) {
			for (te = p->element; te != NULL; te = te->next) {
				TimeElementsEvents[i++] = te->from == 0 ? 1440 : te->from;
				TimeElementsEvents[i++] = te->to == 0 ? 1440 : te->to;
			}
		}
		qsort(TimeElementsEvents, numTimeElements * 2, sizeof(int),
		      (void *)&sgTimeCmp);
		for (i = 0, j = 0; i < numTimeElements * 2; i++) {
			if (j == 0) {
				t[j++] = TimeElementsEvents[i];
			} else {
				if (t[j - 1] != TimeElementsEvents[i])
					t[j++] = TimeElementsEvents[i];
			}
		}
		sgFree(TimeElementsEvents);
		numTimeElements = j;
		TimeElementsEvents = t;
	}
}

int sgTimeNextEvent()
{
	time_t t;
	struct tm *lt;
	int m = 0;
	static int lastval = 0;
	static int index = 0;

#if HAVE_SIGACTION
	struct sigaction act;
#endif
	if (Time == NULL)
		return 0;
	t = time(NULL) + globalDebugTimeDelta;

	lt = localtime(&t);
	m = (lt->tm_hour * 60) + lt->tm_min;

	for (index = 0; index < numTimeElements; index++) {
		if (TimeElementsEvents[index] >= m)
			break;
	}
	lastval = TimeElementsEvents[index];
#if HAVE_SIGACTION
#ifndef SA_NODEFER
#define SA_NODEFER 0
#endif
	act.sa_handler = sgAlarm;
	act.sa_flags = SA_NODEFER | SA_RESTART;
	sigaction(SIGALRM, &act, NULL);
#else
#if HAVE_SIGNAL
	signal(SIGALRM, &sgAlarm);
#else
#endif
#endif
	if (lastval < m)
		m = (((1440 - m) + lastval) * 60) - lt->tm_sec;
	else
		m = ((lastval - m) * 60) - lt->tm_sec;
	if (m <= 0)
		m = 30;
	sgLogDebug("INFO: recalculating alarm in %d seconds", (unsigned int)m);
	alarm((unsigned int)m);
	sgTimeCheck(lt, t);
	sgTimeSetAcl();
	return 0;
}

static int sgTimeCheck(struct tm *lt, time_t t)
{
	struct Time *sg;
	struct TimeElement *te;
	int min;
	if (Time == NULL)
		return -1;
	for (sg = Time; sg != NULL; sg = sg->next) {
		sg->active = 0;
		for (te = sg->element; te != NULL; te = te->next) {
			if (te->wday != 0) {
				if (((1 << lt->tm_wday) & te->wday) != 0) {
					min = (lt->tm_hour * 60) + lt->tm_min;
					if (min >= te->from && min < te->to) {
						sg->active = 1;
						break;
					}
				}
			} else { /* date */
				if (te->fromdate != 0) {
					if (t >= te->fromdate && t <= te->todate) {
						min = (lt->tm_hour * 60) + lt->tm_min;
						if (min >= te->from && min < te->to) {
							sg->active = 1;
							break;
						}
					}
				} else { /* cron */
					if (te->y == -1 || te->y == (lt->tm_year + 1900)) {
						if (te->m == -1 || te->m == (lt->tm_mon + 1)) {
							if (te->d == -1 || te->d == (lt->tm_mday)) {
								min = (lt->tm_hour * 60) + lt->tm_min;
								if (min >= te->from && min < te->to) {
									sg->active = 1;
									break;
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}

static void sgTimeSetAcl()
{
	struct Acl *acl = defaultAcl;
	struct Destination *d;
	struct Source *s;
	struct sgRewrite *rew;

	for (acl = Acl; acl != NULL; acl = acl->next) {
		if (acl->time != NULL) {
			acl->active = acl->time->active;
			if (acl->within == T_OUTSIDE) {
				if (acl->active)
					acl->active = 0;
				else
					acl->active = 1;
			}
			/* Nothing actually sets acl->within to ELSE
			if (acl->next != NULL && acl->next->within == ELSE) {
				if (acl->active == 0)
					acl->next->active = 1;
				else
					acl->next->active = 0;
			}
			*/
		}
	}
	for (d = Dest; d != NULL; d = d->next) {
		if (d->time != NULL) {
			d->active = d->time->active;
			if (d->within == T_OUTSIDE) {
				if (d->active)
					d->active = 0;
				else
					d->active = 1;
			}
		}
	}
	for (s = Source; s != NULL; s = s->next) {
		if (s->time != NULL) {
			s->active = s->time->active;
			if (s->within == T_OUTSIDE) {
				if (s->active)
					s->active = 0;
				else
					s->active = 1;
			}
		}
	}
	for (rew = Rewrite; rew != NULL; rew = rew->next) {
		if (rew->time != NULL) {
			rew->active = rew->time->active;
			if (rew->within == T_OUTSIDE) {
				if (rew->active)
					rew->active = 0;
				else
					rew->active = 1;
			}
		}
	}
}

void sgTimeElementClone()
{
	struct TimeElement *te = lastTimeElement, *tmp;

	if (lastTimeElement == NULL) {
		sgLogFatal("FATAL: No prev TimeElement in sgTimeElementClone !");
	} else {
		sgTimeElementInit();
		lastTimeElement->wday = te->wday;
		lastTimeElement->from = te->from;
		lastTimeElement->to = te->to;
		lastTimeElement->y = te->y;
		lastTimeElement->m = te->m;
		lastTimeElement->d = te->d;
		lastTimeElement->fromdate = te->fromdate;
		lastTimeElement->todate = te->todate;
		tmp = lastTimeElement;
		lastTimeElement = te;
		sgTimeElementEnd();
		lastTimeElement = tmp;
	}
}


