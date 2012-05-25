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

#define _GNU_SOURCE 1

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include "sg.h"
#include "sgLog.h"
#include "sgMemory.h"
#include "sgSetting.h"
#include "sgRequest.h"
#include "sgRequestLog.h"
#include "sgAccessList.h"

struct LogFileStat {
	char *			name;
	FILE *			fd;
	struct LogFileStat *	next;
};

static struct LogFileStat *firstStat = NULL;
static struct LogFileStat *lastStat = NULL;

struct RequestLog {
	struct RequestLog *	next;
	char *			name;
	int			anonymous;
	int			verbose;
	struct LogFileStat *	stat;
};

static struct RequestLog *firstLog = NULL;
static struct RequestLog *lastLog = NULL;

struct RequestLog *defaultRequestLog = NULL;

static void reopenLogFileStat(struct LogFileStat *stat)
{
	if (stat->fd) {
		fclose(stat->fd);
		stat->fd = NULL;
	}

	if ((stat->fd = fopen(stat->name, "a+")) == NULL)
		sgLogError("cannot (re-)open request-log '%s': '%s'", stat->name, strerror(errno));
}

void reopenAllRequestLogs()
{
	struct LogFileStat *now = firstStat;

	for (now = firstStat; now; now = now->next)
		reopenLogFileStat(now);
}

static struct LogFileStat *newLogFileStat(const char *name)
{
	struct LogFileStat *result = sgMalloc(sizeof(struct LogFileStat));

	if (!result)
		return NULL;

	result->name = sgStrdup(name);

	if (!lastStat) {
		firstStat = result;
		lastStat = result;
	} else {
		lastStat->next = result;
		lastStat = result;
	}

	reopenLogFileStat(result);

	return result;
}

static void freeLogFileStat(struct LogFileStat *stat)
{
	if (stat->fd) {
		fclose(stat->fd);
		stat->fd = NULL;
	}

	sgFree(stat->name);
	sgFree(stat);
}

static void freeAllLogFileStats()
{
	struct LogFileStat *now = firstStat;

	while (now) {
		struct LogFileStat *next = now->next;
		freeLogFileStat(now);
		now = next;
	}

	firstStat = lastStat = NULL;
}

static char *absLogName(const char *name)
{
	char *result = NULL;

	if (*name != '/') {
		const char *dir;

		if ((dir = getSetting("logdir")) == NULL)
			dir = DEFAULT_LOGDIR;

		asprintf(&result, "%s/%s", dir, name);
	} else {
		result = sgStrdup(name);
	}

	return result;
}

static struct LogFileStat *findLogFileStat(const char *name)
{
	struct LogFileStat *now;
	char *fileName = absLogName(name);

	for (now = firstStat; now; now = now->next) {
		if (strcmp(now->name, fileName) == 0) {
			sgFree(fileName);
			return now;
		}
	}

	sgFree(fileName);

	return NULL;
}

struct RequestLog *newRequestLog(const char *name, int anonymous, int verbose)
{
	struct RequestLog *result = sgMalloc(sizeof(struct RequestLog));
	char *fileName = absLogName(name);

	if (!result)
		return NULL;

	if ((result->stat = findLogFileStat(fileName)) == NULL) {
		if ((result->stat = newLogFileStat(fileName)) == NULL) {
			sgFree(result);
			sgFree(fileName);
			return NULL;
		}
	}

	result->verbose = verbose;
	result->anonymous = anonymous;

	if (!lastLog) {
		firstLog = result;
		lastLog = result;
	} else {
		lastLog->next = result;
		lastLog = result;
	}

	sgFree(fileName);
	return result;
}

struct RequestLog *findRequestLog(const char *name)
{
	struct RequestLog *now;
	char *fileName = absLogName(name);

	for (now = firstLog; now; now = now->next) {
		if (strcmp(now->stat->name, name) == 0) {
			sgFree(fileName);
			return now;
		}
	}

	sgFree(fileName);
	return NULL;
}

static void freeRequestLog(struct RequestLog *log)
{
	sgFree(log);
}

void freeAllRequestLogs()
{
	struct RequestLog *now = firstLog;

	while (now) {
		struct RequestLog *next = now->next;
		freeRequestLog(now);
		now = next;
	}

	firstLog = lastLog = defaultRequestLog = NULL;

	freeAllLogFileStats();
}

void setDefaultRequestLog(struct RequestLog *log)
{
	if (defaultRequestLog != NULL) {
		sgLogError("default request log already set");
		return;
	}

	defaultRequestLog = log;
}


void doRequestLog(struct RequestLog *		log,
		  const struct SquidInfo *	req,
		  const char *			srcClass,
		  const char *			dstClass,
		  const char *			rewrite,
		  enum AccessResults		result)
{
	char *action = "";

	if (log->stat->fd == NULL)
		return;

	switch (result) {
	case ACCESS_GRANTED:
		if (!rewrite) {
			action = "PASS";
			if (!log->verbose)
				return;
		} else {
			action = "REWRITE";
		}
		break;
	case ACCESS_DENIED:
		if (!rewrite)
			action = "DENY";
		else
			action = "REDIRECT";
		break;
	default:
		action = "?";
		break;
	}

	fprintf(log->stat->fd, "Request(%s/%s/%s) %s %s/%s %s %s %s\n",
		srcClass,
		dstClass,
		(rewrite && *rewrite ? rewrite : "-"),
		req->orig,
		req->src,
		((*req->srcDomain) ? req->srcDomain : "-"),
		((*req->ident) && !(log->anonymous) ? req->ident : "-"),
		((*req->method) ? req->method : "-"),
		action
		);

	fflush(log->stat->fd);
}
