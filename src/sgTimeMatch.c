/*
 * By accepting this notice, you agree to be bound by the following
 * agreements:
 *
 * This software product, squidGuard, is copyrighted
 * (C) 2012, Andreas Hofmeister, Collax GmbH,
 * (C) 1998-2009 by Christine Kronberg, Shalla Secure Services.
 * All rights reserved.
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

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sgTimeMatch.h"
#include "sgMemory.h"
#include "sgLog.h"

static int nextTmUpdate = 0;
static struct tm tm;

struct TimeRangeSpec {
	unsigned char	min_from;
	unsigned char	min_to;
	unsigned char	hour_from;
	unsigned char	hour_to;
};

enum MatchTypes {
	DMT_WEEKLY,
	DMT_DAY,
};

struct WeekDaySpec {
	unsigned char wdays;
};

struct YearDaySpec {
	int	year_from;
	int	year_to;
	char	month_from;
	char	month_to;
	char	day_from;
	char	day_to;
};

struct TimeMatchElement {
	struct TimeMatchElement *	next;
	enum MatchTypes			type;
	struct TimeRangeSpec		time;
	union {
		struct WeekDaySpec	weekly;
		struct YearDaySpec	daily;
	} u;
};

static struct TimeMatch *firstTimeMatch;
static struct TimeMatch *lastTimeMatch;

static struct TimeMatchElement *newTimeMatchElement(enum MatchTypes type)
{
	struct TimeMatchElement *result = sgMalloc(sizeof(struct TimeMatchElement));

	if (result == NULL)
		return NULL;

	memset(result, 0, sizeof(*result));
	result->type = type;

	return result;
}

void setTimeValues(struct TimeMatchElement *match, const char *from, const char *to)
{
	int fh = 0;
	int fm = 0;
	int th = 0;
	int tm = 0;

	sscanf(from, "%d:%d", &fh, &fm);
	if ((fh < 0 && fh > 24) && (fm < 0 && fm > 59))
		sgLogFatal("FATAL: time formaterror");

	match->time.hour_from = fh;
	match->time.min_from = fm;

	sscanf(to, "%d:%d", &th, &tm);
	if ((th < 0 && th > 24) && (tm < 0 && tm > 59))
		sgLogFatal("FATAL: time formaterror");

	match->time.hour_to = th;
	match->time.min_to = tm;
}

static void freeTimeMatchElement(struct TimeMatchElement *match)
{
	sgFree(match);
}

struct TimeMatch *newTimeMatch(const char *name)
{
	struct TimeMatch *result = sgMalloc(sizeof(struct TimeMatch));

	if (result == NULL)
		return NULL;

	result->name = sgStrdup(name);
	result->nextCheck = 0;
	result->lastResult = 0;

	result->next = NULL;

	result->firstElement = NULL;
	result->lastElement = NULL;

	if (lastTimeMatch == NULL) {
		firstTimeMatch = result;
		lastTimeMatch = result;
	} else {
		lastTimeMatch->next = result;
		lastTimeMatch = result;
	}

	return result;
}

static void freeTimeMatch(struct TimeMatch *match)
{
	struct TimeMatchElement *el;

	if (match == NULL)
		return;

	el = match->firstElement;
	while (el) {
		struct TimeMatchElement *next = el->next;
		freeTimeMatchElement(el);
		el = next;
	}
	sgFree(match->name);
	sgFree(match);
}

void freeAllTimeMatches()
{
	struct TimeMatch *now = firstTimeMatch;

	while (now) {
		struct TimeMatch *next = now->next;
		freeTimeMatch(now);
		now = next;
	}
	firstTimeMatch = NULL;
	lastTimeMatch = NULL;
}

struct TimeMatch *findTimeMatch(const char *name)
{
	struct TimeMatch *now;

	for (now = firstTimeMatch; now != NULL; now = now->next)
		if (strcmp(now->name, name) == 0)
			return now;

	return NULL;
}

static void addTimeElementToMatch(struct TimeMatch *match, struct TimeMatchElement *el)
{
	if (match->firstElement == NULL) {
		match->firstElement = el;
		match->lastElement = el;
	} else {
		match->lastElement->next = el;
		match->lastElement = el;
	}
}

struct TimeMatchElement *addWeeklyElement(struct TimeMatch *match, const char *days)
{
	struct TimeMatchElement *result = newTimeMatchElement(DMT_WEEKLY);
	const char *p = days;
	unsigned char wday = 0;
	int err = 0;

	if (result == NULL)
		return NULL;

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
			sgLogFatal("FATAL: weekday formaterror");
			err++;
			break;
		}
		p++;
	}

	result->u.weekly.wdays = wday;

	if (err) {
		freeTimeMatchElement(result);
		return NULL;
	}

	addTimeElementToMatch(match, result);
	return result;
}

struct TimeMatchElement *addWeekdayElement(struct TimeMatch *match, const char *days)
{
	struct TimeMatchElement *result = newTimeMatchElement(DMT_WEEKLY);
	char *copy = sgStrdup(days);
	char *p = NULL;
	unsigned char wday = 0;

	if (result == NULL) {
		freeTimeMatchElement(result);
		sgFree(copy);
		return NULL;
	}

	p = strtok(copy, " \t,");
	if (p == NULL) {
		freeTimeMatchElement(result);
		sgFree(copy);
		return NULL;
	}

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
		/* FIXME: else what ? */
		p = strtok(NULL, " \t,");
	} while ((p = strtok(NULL, " \t,")) != NULL);

	result->u.weekly.wdays = wday;
	sgFree(copy);

	return result;
}

struct TimeMatchElement *dupWeeklyElement(struct TimeMatch *match, struct TimeMatchElement *orig)
{
	struct TimeMatchElement *result = newTimeMatchElement(DMT_WEEKLY);

	if (result == NULL)
		return NULL;

	memcpy(&(result->u), &(orig->u), sizeof(orig->u));
	addTimeElementToMatch(match, result);

	return result;
}

struct TimeMatchElement *addDateElement(struct TimeMatch *match, const char *date, const char *date_to)
{
	struct TimeMatchElement *result = newTimeMatchElement(DMT_DAY);
	int y = 0;
	int m = 0;
	int d = 0;

	if (result == NULL)
		return NULL;

	sscanf(date, "%4d%*[.-]%2d%*[.-]%2d", &y, &m, &d);

	if (m < 1 || m > 12 || d < 1 || d > 31) {
		freeTimeMatchElement(result);
		return NULL;
	}

	result->u.daily.year_from = result->u.daily.year_to = y;
	result->u.daily.month_from = result->u.daily.month_to = m;
	result->u.daily.day_from = result->u.daily.day_to = d;

	if (date_to != NULL) {
		sscanf(date_to, "%4d%*[.-]%2d%*[.-]%2d", &y, &m, &d);

		if (m < 1 || m > 12 || d < 1 || d > 31) {
			freeTimeMatchElement(result);
			return NULL;
		}

		result->u.daily.year_to = y;
		result->u.daily.month_to = m;
		result->u.daily.day_to = d;
	}

	addTimeElementToMatch(match, result);
	return result;
}

struct TimeMatchElement *addCronDateElement(struct TimeMatch *match, const char *date)
{
	struct TimeMatchElement *result = newTimeMatchElement(DMT_DAY);
	char *copy = NULL;
	char *p = NULL;

	if (result == NULL)
		return NULL;

	if ((copy = sgStrdup(date)) == NULL) {
		freeTimeMatchElement(result);
		return NULL;
	}

	if ((p = strtok(copy, "-.")) != NULL) {
		if (*p == '*')
			result->u.daily.year_from = result->u.daily.year_to = -1;
		else
			result->u.daily.year_from = result->u.daily.year_to = atoi(p);

		if ((p = strtok(NULL, "-.")) != NULL) {
			if (*p == '*')
				result->u.daily.month_from = result->u.daily.month_to = -1;
			else
				result->u.daily.month_from = result->u.daily.month_to = atoi(p);

			if ((p = strtok(NULL, "-.")) != NULL) {
				if (*p == '*')
					result->u.daily.day_from = result->u.daily.day_to = -1;
				else
					result->u.daily.day_from = result->u.daily.day_to = atoi(p);
			}
		}
	}

	addTimeElementToMatch(match, result);
	sgFree(copy);
	return result;
}

struct TimeMatchElement *dupDateElement(struct TimeMatch *match, struct TimeMatchElement *orig)
{
	struct TimeMatchElement *result = newTimeMatchElement(DMT_DAY);

	if (result == NULL)
		return NULL;

	memcpy(&(result->u), &(orig->u), sizeof(orig->u));
	result->next = NULL;
	addTimeElementToMatch(match, result);

	return result;
}

static int matchTimeRangeSpec(struct TimeRangeSpec *spec, struct tm *tm)
{
	if ((tm->tm_hour < spec->hour_from) || (tm->tm_hour > spec->hour_to)) {
		sgLogDebug("hour does not match, %d < %d > %d", spec->hour_from, tm->tm_hour, spec->hour_to);
		return 0;
	}

	if ((tm->tm_hour == spec->hour_from && tm->tm_min < spec->min_from) ||
	    (tm->tm_hour == spec->hour_to && tm->tm_min > spec->min_to)) {
		sgLogDebug("minute does not match, %d < %d > %d", spec->min_from, tm->tm_min, spec->min_to);
		return 0;
	}

	sgLogDebug("time range does match");
	return 1;
}

static int matchWeekDaySpec(struct WeekDaySpec *spec, struct tm *tm)
{
	if (!(spec->wdays & (1 << tm->tm_wday))) {
		sgLogDebug("weekday does not match, %x & %x", spec->wdays, 1 << tm->tm_wday);
		return 0;
	}

	sgLogDebug("weekday does match");
	return 1;
}

static int matchYearDaySpec(struct YearDaySpec *spec, struct tm *tm)
{
	if (spec->year_from >= 0) {
		int y = tm->tm_year + 1900;
		if ((y < spec->year_from) || (y > spec->year_to)) {
			sgLogDebug("year does not match, %d < %d > %d", spec->year_from, y, spec->year_to);
			return 0;
		}
	}

	if (spec->month_from >= 0) {
		int m = tm->tm_mon + 1;
		if ((m < spec->month_from) || (m > spec->month_to)) {
			sgLogDebug("month does not match, %d < %d > %d", spec->month_from, m, spec->month_to);
			return 0;
		}
	}

	if (spec->day_from >= 0) {
		if ((tm->tm_mday < spec->day_from) || (tm->tm_mday > spec->day_to)) {
			sgLogDebug("day does not match, %d < %d > %d", spec->day_from, tm->tm_mday, spec->day_to);
			return 0;
		}
	}

	sgLogDebug("date does match");
	return 1;
}

static int matchElement(struct TimeMatchElement *spec, struct tm *tm)
{
	int result = 0;

	if (spec->type == DMT_WEEKLY)
		result = matchWeekDaySpec(&(spec->u.weekly), tm);
	else
		result = matchYearDaySpec(&(spec->u.daily), tm);

	if (result == 0)
		return 0;

	return matchTimeRangeSpec(&(spec->time), tm);
}

int matchTime(struct TimeMatch *match)
{
	struct TimeMatchElement *el;
	time_t now = time(NULL);
	int result = 0;

	if (now < match->nextCheck)
		return match->lastResult;

	if (now > nextTmUpdate) {
		struct tm tm2;

		localtime_r(&now, &tm);

		memcpy(&tm2, &tm, sizeof(struct tm));
		tm2.tm_sec = 0;
		tm2.tm_min++;
		nextTmUpdate = mktime(&tm2);

		sgLogDebug("next tm update in %ds", nextTmUpdate - now);
	}

	sgLogDebug("check time range %s", match->name);

	for (el = match->firstElement; el; el = el->next)
		if ((result = matchElement(el, &tm)) > 0)
			break;

	match->nextCheck = nextTmUpdate;
	match->lastResult = result;

	return result;
}
