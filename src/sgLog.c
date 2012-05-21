/*
 * By accepting this notice, you agree to be bound by the following
 * agreements:
 *
 * This software product, squidGuard, is copyrighted (C) 1998-2009
 * by Christine Kronberg, Shalla Secure Services. All rights reserved.
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

#define _GNU_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <stdarg.h>

#include "config.h"

#include "sg.h"
#include "sgMemory.h"
#include "sgLog.h"
#include "sgSetting.h"

extern int inEmergencyMode;

struct ErrorLog {
	char *	filename;
	FILE *	fd;
};

char *globalLogDir = NULL;

static int globalDebug = 0;
static int globalSyslog = 0;

static char *level2str[] = {
	"EMERG",        /* LOG_EMERG       0 */
	"ALERT",        /* LOG_ALERT       1 */
	"CRITICAL",     /* LOG_CRIT        2 */
	"ERROR",        /* LOG_ERR         3 */
	"WARNING",      /* LOG_WARNING     4 */
	"NOTICE",       /* LOG_NOTICE      5 */
	"INFO",         /* LOG_INFO        6 */
	"DEBUG",        /* LOG_DEBUG       7 */
};

static struct ErrorLog *errorLog = NULL;

static int reopenErrorLog(struct ErrorLog *log)
{
	if (log->fd != NULL) {
		fclose(log->fd);
		log->fd = NULL;
	}

	if ((log->fd = fopen(log->filename, "a+")) == NULL) {
		sgLogError("cannot open error log '%s': %s", log->filename, strerror(errno));
		return 0;
	}

	return 1;
}

static struct ErrorLog *newErrorLog(const char *filename)
{
	struct ErrorLog *result = sgMalloc(sizeof(struct ErrorLog));

	result->filename = sgStrdup(filename);
	result->fd = NULL;

	if (!reopenErrorLog(result)) {
		sgFree(result->filename);
		sgFree(result);
		return NULL;
	}

	return result;
}

void freeErrorLog(struct ErrorLog *log)
{
	if (log->fd) {
		fclose(log->fd);
		log->fd = NULL;
	}

	sgFree(log->filename);
	sgFree(log);
}

static char *niso()
{
	static char buf[20];
	time_t tp = time(NULL);
	struct tm *lc;

	lc = localtime(&tp);

	sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d", lc->tm_year + 1900, lc->tm_mon + 1,
		lc->tm_mday, lc->tm_hour, lc->tm_min, lc->tm_sec);
	return buf;
}

void setDebugFlag(const char *value)
{
	globalDebug = booleanSetting(value);
}

void setSyslogFlag(const char *value)
{
	globalSyslog = booleanSetting(value);
}

void sgSetGlobalErrorLogFile()
{
	char *file = NULL;
	char *dir;
	size_t len;

	if (globalDebug)
		return;

	if (globalLogDir == NULL)
		dir = DEFAULT_LOGDIR;
	else
		dir = globalLogDir;

	len = strlen(DEFAULT_LOGFILE) + strlen(dir) + 2;
	file = sgMalloc(len);

	snprintf(file, len, "%s/%s", dir, DEFAULT_LOGFILE);

	if (errorLog)
		freeErrorLog(errorLog);
	errorLog = newErrorLog(file);
	sgFree(file);
}

static void doFileLog(const char *prefix, const char *message)
{
	FILE *fd;

	if (errorLog != NULL)
		fd = errorLog->fd;

	if (fd == NULL)
		fd = stderr;

	fprintf(fd, "%s [%d] %s: %s\n", niso(), getpid(), prefix, message);
	fflush(fd);
}

static void doLog(int level, const char *message)
{
	if (globalSyslog)
		syslog(level, "%s", message);
	else
		doFileLog(level2str[level], message);
}


void sgLogDebug(char *format, ...)
{
	char *msg = NULL;
	va_list ap;

	if (!globalDebug)
		return;

	va_start(ap, format);
	vasprintf(&msg, format, ap);
	va_end(ap);

	doLog(LOG_DEBUG, msg);
	sgFree(msg);
}


void sgLogInfo(char *format, ...)
{
	char *msg = NULL;
	va_list ap;

	va_start(ap, format);
	vasprintf(&msg, format, ap);
	va_end(ap);

	doLog(LOG_INFO, msg);
	sgFree(msg);
}

void sgLogNotice(char *format, ...)
{
	char *msg = NULL;
	va_list ap;

	va_start(ap, format);
	vasprintf(&msg, format, ap);
	va_end(ap);

	doLog(LOG_NOTICE, msg);
	sgFree(msg);
}

void sgLogWarn(char *format, ...)
{
	char *msg = NULL;
	va_list ap;

	va_start(ap, format);
	vasprintf(&msg, format, ap);
	va_end(ap);

	doLog(LOG_WARNING, msg);
	sgFree(msg);
}

void sgLogError(char *format, ...)
{
	char *msg = NULL;
	va_list ap;

	va_start(ap, format);
	vasprintf(&msg, format, ap);
	va_end(ap);

	doLog(LOG_ERR, msg);
	sgFree(msg);
}

void sgLogFatal(char *format, ...)
{
	char *msg = NULL;
	va_list ap;

	va_start(ap, format);
	vasprintf(&msg, format, ap);
	va_end(ap);

	doLog(LOG_CRIT, msg);
	inEmergencyMode = 1;
	sgFree(msg);
}
