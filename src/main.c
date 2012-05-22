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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

#include "sg.h"
#include "sgReadBuffer.h"
#include "sgMemory.h"
#include "sgLog.h"
#include "sgAccessList.h"
#include "sgSetting.h"
#include "sgGroup.h"
#include "sgRequest.h"

#include "HTEscape.h"

struct LogFile *globalLogFile = NULL;

int globalUpdate = 0;
int passthrough = 0;
int showBar = 0;   /* Do not display the progress bar. */
char *globalCreateDb = NULL;

int inEmergencyMode = 0;
int authzMode = 0;      /* run as authorization helper, not as redirector */

static void authzExtra(struct AccessList *acl)
{
	char msg[MAX_BUF];
	char *escaped = NULL;

	snprintf(msg, MAX_BUF, "Request matched rule %s", acl->name);
	escaped = HTEscape(msg, URL_XALPHAS);
	fprintf(stdout, " log=%s", escaped);
	fprintf(stdout, " message=%s", escaped);
	sgFree(escaped);

	if (acl->tag) {
		escaped = HTEscape(acl->tag, URL_XALPHAS);
		fprintf(stdout, " tag=%s", escaped);
		sgFree(escaped);
	}

	fflush(stdout);
}

static void grantAccess(struct AccessList *acl)
{
	sgLogDebug("Granted access, rule %s matched.", acl->name);

	if (!authzMode) {
		puts("");
		return;
	}

	fprintf(stdout, "OK");
	authzExtra(acl);
	fprintf(stdout, "\n");

	fflush(stdout);
}

static void denyAccess(struct AccessList *acl, const char *redirect, const struct SquidInfo *req)
{
	sgLogDebug("Denied access, rule %s matched.", acl->name);

	if (!authzMode) {
		fprintf(stdout, "%s %s/%s %s %s\n",
		        redirect,
			req->src,
			*(req->srcDomain) ? req->srcDomain : "-",
			*(req->ident) ? req->ident : "-",
			*(req->method) ? req->method : "-");
		fflush(stdout);
		return;
	}

	fprintf(stdout, "ERR");
	authzExtra(acl);
	fprintf(stdout, "\n");

	fflush(stdout);
}

static void denyOnError(const char *message)
{
	char *escaped = NULL;

	if (!authzMode) {
		/* FIXME: emergency redirect here */
		fprintf(stdout, "\n");
		fflush(stdout);
	}

	escaped = HTEscape(message, URL_XALPHAS);
	fprintf(stdout, "ERR log=%s message=%s\n", escaped, escaped);
	sgFree(escaped);

	fflush(stdout);
}

static void allowOnError(const char *message)
{
	char *escaped = NULL;

	if (!authzMode) {
		fprintf(stdout, "\n");
		fflush(stdout);
	}

	escaped = HTEscape(message, URL_XALPHAS);
	fprintf(stdout, "OK log=%s message=%s\n", escaped, escaped);
	sgFree(escaped);

	fflush(stdout);
}

static void usage()
{
	fprintf(stderr,
		"Usage: squidGuard [-u] [-C block] [-t time] [-c file] [-v] [-d] [-P]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -v          : show version number\n");
	fprintf(stderr, "  -d          : all errors to stderr\n");
	fprintf(stderr, "  -b          : switch on the progress bar when updating the blacklists\n");
	fprintf(stderr, "  -c file     : load alternate configfile\n");
	fprintf(stderr, "  -u          : update .db files from .diff files\n");
	fprintf(stderr, "  -z          : run as external acl helper instead as a redirector\n");
	fprintf(stderr, "  -C file|all : create new .db files from urls/domain files\n");
	fprintf(stderr, "                specified in \"file\".\n");
	fprintf(stderr, "  -P          : do not go into emergency mode when an error with the \n");
	fprintf(stderr, "                blacklists is encountered.\n");
}


static char *configFile = NULL;
static char *optDebug = "0";
static char *optSyslog = "0";

static int parseOptions(int argc, char **argv)
{
	char c;

	while ((c = getopt(argc, argv, "hbdsuPC:t:c:vz")) != EOF) {
		switch (c) {
		case 'c':
			configFile = strdup(optarg);
			break;
		case 'b':
			showBar = 1;
		case 'd':
			optDebug = "1";
			break;
		case 'C':
			globalCreateDb = strdup(optarg);
			break;
		case 'P':
			passthrough = 1;
			break;
		case 's':
			optSyslog = "1";
			break;
		case 'u':
			globalUpdate = 1;
			break;
		case 'v':
			fprintf(stderr, "SquidGuard: %s\n", VERSION);
			exit(0);
			break;
		case 'z':
			authzMode = 1;
			break;
		case '?':
		case 'h':
		default:
			usage();
			return 0;
		}
	}

	return 1;
}

static void registerSettings()
{
	registerSetting("dbhome", DEFAULT_DBHOME, NULL);

	registerSetting("logdir", DEFAULT_LOGDIR, NULL);
	registerSetting("debug", optDebug, setDebugFlag);
	registerSetting("syslog", optSyslog, setSyslogFlag);

	registerSetting("groupttl", "600", setGroupCacheTTL);
	registerSetting("reverselookup", "false", setReverseLookup);
}

int main(int argc, char **argv, char **envp)
{
	struct ReadBuffer * buf = newReadBuffer(fileno(stdin));
	char * line = NULL;
	size_t linesz = 0;
	int act = 0;

	setupSignals();

	openlog("squidGuard", LOG_PID | LOG_NDELAY | LOG_CONS, SYSLOG_FAC);

	if (!parseOptions(argc, argv)) {
		closelog();
		exit(1);
	}

	registerSettings();

	//sgSetGlobalErrorLogFile();
	sgReadConfig(configFile);
	sgSetGlobalErrorLogFile();

	sgLogInfo("squidGuard %s started", VERSION);

	if (globalUpdate || globalCreateDb != NULL) {
		sgLogInfo("db update done");
		sgLogInfo("squidGuard stopped.");
		closelog();

		freeAllLists();
		exit(0);
	}

	sgLogInfo("squidGuard ready for requests");

	while ((act = doBufferRead(buf, &line, &linesz)) >= 0) {
		struct AccessList *acl;
		struct SquidInfo request;

		if (act == 0) {
			//sgReloadConfig();
			continue;
		}

		if (authzMode == 1) {
			if (parseAuthzLine(line, &request) != 1) {
				sgLogError("ERROR: Error parsing squid acl helper line");
				denyOnError("Error parsing squid acl helper line");
				continue;
			}
		} else {
			if (parseLine(line, &request) != 1) {
				sgLogError("ERROR: Error parsing squid redirector line");
				denyOnError("Error parsing squid acl helper line");
				continue;
			}
		}

		if (inEmergencyMode) {
			const char *message = "squidGuard is in emergency mode, check configuration";
			if (passthrough)
				allowOnError(message);
			else
				denyOnError(message);
			continue;
		}

		for (acl = getFirstAccessList(); acl; acl = acl->next) {
			char *redirect = NULL;
			enum AccessResults access = checkAccess(acl, &request, &redirect);

			if (access == ACCESS_UNDEFINED)
				continue;

			if (access == ACCESS_GRANTED) {
				grantAccess(acl);
				break;
			}

			denyAccess(acl, redirect, &request);
			sgFree(redirect);

			break;
		}

		fflush(stdout);
		/*
		 * if (sig_hup)
		 *      sgReloadConfig();
		 */
	}

	sgLogNotice("squidGuard stopped");
	closelog();
	freeAllLists();
	sgFree(line);
	freeReadBuffer(buf);
	exit(0);
}
