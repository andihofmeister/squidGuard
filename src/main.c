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

#include "sg.h"
#include "sgMemory.h"
#include "sgLog.h"
#include "HTEscape.h"
#ifdef USE_SYSLOG
#include <syslog.h>
#endif

struct Setting *lastSetting = NULL;
struct Setting *Setting = NULL;                        /* linked list, Calloc */

struct Source *lastSource = NULL;
struct Source *Source = NULL;                  /* linked list, Calloc */

struct Destination *lastDest = NULL;
struct Destination *Dest = NULL;               /* linked list, Calloc */

struct sgRewrite *lastRewrite = NULL;
struct sgRewrite *Rewrite = NULL;              /* linked list, Calloc */
struct sgRegExp *lastRewriteRegExec = NULL;

struct Time *lastTime = NULL;
struct Time *Time = NULL;                      /* linked list, Calloc */

struct LogFileStat *globalErrorLog = NULL;
struct LogFile *globalLogFile = NULL;

struct LogFileStat *lastLogFileStat;
struct LogFileStat *LogFileStat;               /* linked list, Calloc */

struct TimeElement *lastTimeElement = NULL;
struct TimeElement *TimeElement = NULL;

struct Acl *lastAcl = NULL;
struct Acl *defaultAcl = NULL;
struct Acl *Acl = NULL;                                /* linked list, Calloc */
struct AclDest *lastAclDest = NULL;

struct sgRegExp *lastRegExpDest;

struct Source *lastActiveSource;

char **globalArgv;
char **globalEnvp;
int globalDebugTimeDelta = 0;
int globalDebug = 0;
int globalPid = 0;
int globalUpdate = 0;
int passthrough = 0;
int showBar = 0;   /* Do not display the progress bar. */
char *globalCreateDb = NULL;
int sig_hup = 0;
int sig_alrm = 0;
int sgtime = 0;
char *globalLogDir = NULL;
int globalSyslog = 0;

int inEmergencyMode = 0;
int authzMode = 0;	/* run as authorization helper, not as redirector */

static void authzExtra(struct Acl *acl) {
	char msg[MAX_BUF];
	char * escaped = NULL;

	snprintf(msg,MAX_BUF,"Request matched rule %s", acl->name);
	escaped = HTEscape(msg,URL_XALPHAS);
	fprintf(stdout, " log=%s", escaped);
	fprintf(stdout, " message=%s", escaped);
	sgFree(escaped);

	if (acl->tag) {
		escaped = HTEscape(acl->tag,URL_XALPHAS);
		fprintf(stdout, " tag=%s", escaped);
		sgFree(escaped);
	}

	fflush(stdout);
}

static void grantAccess(struct Acl *acl)
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

static void denyAccess(struct Acl *acl, const char *redirect)
{
	sgLogDebug("Denied access, rule %s matched.", acl->name);

	if (!authzMode) {
		fprintf(stdout, "%s\n", redirect);
		fflush(stdout);
		return;
	}

	fprintf(stdout, "ERR");
	authzExtra(acl);
	fprintf(stdout, "\n");

	fflush(stdout);
}

static void denyOnError(const char * message)
{
	char * escaped = NULL;

	if (!authzMode) {
		/* FIXME: emergency redirect here */
		fprintf(stdout, "\n");
		fflush(stdout);
	}

	escaped = HTEscape(message,URL_XALPHAS);
	fprintf(stdout, "ERR log=%s message=%s\n", escaped, escaped);
	sgFree(escaped);

	fflush(stdout);
}

static void allowOnError(const char * message) {
	char * escaped = NULL;

	if (!authzMode) {
		fprintf(stdout, "\n");
		fflush(stdout);
	}

	escaped = HTEscape(message,URL_XALPHAS);
	fprintf(stdout, "OK log=%s message=%s\n", escaped, escaped);
	sgFree(escaped);

	fflush(stdout);
}

int main(int argc, char **argv, char **envp)
{
	extern int groupDebug;
	int ch;
	struct SquidInfo squidInfo;
	struct Source *src;
	struct Acl *acl;
	struct timeval start_time, ready_time, stop_time;
	char buf[MAX_BUF];
	char *redirect, tmp[MAX_BUF];
	char *configFile = NULL;
	extern char *krbRealm;
	time_t t;
#if HAVE_SIGACTION
	struct sigaction act;
#endif
	gettimeofday(&start_time, NULL);
	progname = argv[0];
	globalPid = getpid();
#ifdef USE_SYSLOG
	openlog("squidGuard", LOG_PID | LOG_NDELAY | LOG_CONS, SYSLOG_FAC);
#endif
	while ((ch = getopt(argc, argv, "hbduPC:t:c:vGr:z")) != EOF) {
		switch (ch) {
		case 'd':
			globalDebug = 1;
			break;
		case 'c':
			configFile = optarg;
			break;
		case 'b':
			showBar = 1;
		case 'C':
			globalCreateDb = optarg;
			break;
		case 'P':
			passthrough = 1;
			break;
		case 'u':
			globalUpdate = 1;
			break;
		case 'v':
			fprintf(stderr, "SquidGuard: %s %s\n", VERSION, db_version(NULL, NULL, NULL));
			exit(0);
			break;
		case 't':
			if ((t = iso2sec(optarg)) == -1) {
				fprintf(stderr, "-t dateformat error, should be yyyy-mm-ddTHH:MM:SS\n");
				exit(0);
			}
			if (t < 0) {
				fprintf(stderr, "-t date have to after 1970-01-01T01:00:00\n");
				exit(0);
			}
			sgLogDebug("DEBUG: squidGuard emulating date %s", niso(t));
			globalDebugTimeDelta = t - start_time.tv_sec;
			start_time.tv_sec = start_time.tv_sec + globalDebugTimeDelta;
			break;
		case 'G':
			groupDebug = 1;
			break;
		case 'r':
			krbRealm = optarg;
			break;
		case 'z':
			authzMode = 1;
			break;
		case '?':
		case 'h':
		default:
			usage();
		}
	}

	globalArgv = argv;
	globalEnvp = envp;
	sgSetGlobalErrorLogFile();
	sgReadConfig(configFile);
	sgSetGlobalErrorLogFile();
	sgLogNotice("INFO: squidGuard %s started (%d.%03d)",
		    VERSION, start_time.tv_sec, start_time.tv_usec / 1000);

	if (globalUpdate || globalCreateDb != NULL) {
		sgLogNotice("INFO: db update done");
		gettimeofday(&stop_time, NULL);
		stop_time.tv_sec = stop_time.tv_sec + globalDebugTimeDelta;
		sgLogNotice("INFO: squidGuard stopped (%d.%03d)", stop_time.tv_sec, stop_time.tv_usec / 1000);
#ifdef USE_SYSLOG
		closelog();
#endif
		exit(0);
	}

	if (!inEmergencyMode) {
		sgTimeElementSortEvents();
		sgTimeNextEvent();
	}
#if HAVE_SIGACTION
#ifndef SA_NODEFER
#define SA_NODEFER 0
#endif
	act.sa_handler = sgHandlerSigHUP;
	act.sa_flags = SA_NODEFER | SA_RESTART;
	sigaction(SIGHUP, &act, NULL);
#else
#if HAVE_SIGNAL
	signal(SIGHUP, sgHandlerSigHUP);
#else
#endif
#endif
	gettimeofday(&ready_time, NULL);
	ready_time.tv_sec = ready_time.tv_sec + globalDebugTimeDelta;
	sgLogNotice("INFO: squidGuard ready for requests (%d.%03d)",
		    ready_time.tv_sec, ready_time.tv_usec / 1000);
	tmp[MAX_BUF - 1] = '\0';
	while (1) {
		while (fgets(buf, MAX_BUF, stdin) != NULL) {

			if (sig_hup)
				sgReloadConfig();

			if (authzMode == 1) {
				if (parseAuthzLine(buf, &squidInfo) != 1) {
					sgLogError("ERROR: Error parsing squid acl helper line");
					denyOnError("Error parsing squid acl helper line");
					continue;
				}
			} else {
				if (parseLine(buf, &squidInfo) != 1) {
					sgLogError("ERROR: Error parsing squid redirector line");
					denyOnError("Error parsing squid acl helper line");
					continue;
				}
			}

			if (inEmergencyMode) {
				const char * message = "squidGuard is in emergency mode, check configuration";
				if (passthrough) {
					allowOnError(message);
				} else {
					denyOnError(message);
				}
				continue;
			}

			src = Source;
			for (;; ) {
				strncpy(tmp, squidInfo.src, MAX_BUF - 1);
				tmp[MAX_BUF - 1] = 0; /* force null termination */
				globalLogFile = NULL;
				src = sgFindSource(src, tmp, squidInfo.ident, squidInfo.srcDomain);
				acl = sgAclCheckSource(src);
				if ((redirect = sgAclAccess(src, acl, &squidInfo)) == NULL ||
				    redirect == NEXT_SOURCE) {
					if (src == NULL || (src->cont_search == 0 && redirect != NEXT_SOURCE)) {
						grantAccess(acl);
						break;
					} else
					if (src->next != NULL) {
						src = src->next;
						continue;
					} else {
						grantAccess(acl);
						break;
					}
				} else {
					denyAccess(acl, redirect);
					break;
				}
			} /*for(;;)*/

			fflush(stdout);
			if (sig_hup)
				sgReloadConfig();
		}
#if !HAVE_SIGACTION
#if HAVE_SIGNAL
		if (errno != EINTR) {
			gettimeofday(&stop_time, NULL);
			stop_time.tv_sec = stop_time.tv_sec + globalDebugTimeDelta;
			sgLogNotice("INFO: squidGuard stopped (%d.%03d)", stop_time.tv_sec, stop_time.tv_usec / 1000);
#ifdef USE_SYSLOG
			closelog();
#endif
			exit(2);
		}
#endif
#else
		gettimeofday(&stop_time, NULL);
		stop_time.tv_sec = stop_time.tv_sec + globalDebugTimeDelta;
		sgLogNotice("INFO: squidGuard stopped (%d.%03d)", stop_time.tv_sec, stop_time.tv_usec / 1000);
#ifdef USE_SYSLOG
		closelog();
#endif
		exit(0);
#endif
	}
	exit(0);
}

void usage()
{
	fprintf(stderr,
		"Usage: squidGuard [-u] [-C block] [-t time] [-c file] [-v] [-d] [-P]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -v          : show version number\n");
	fprintf(stderr, "  -d          : all errors to stderr\n");
	fprintf(stderr, "  -b          : switch on the progress bar when updating the blacklists\n");
	fprintf(stderr, "  -c file     : load alternate configfile\n");
	fprintf(stderr, "  -t time     : specify startup time in the format: yyyy-mm-ddTHH:MM:SS\n");
	fprintf(stderr, "  -u          : update .db files from .diff files\n");
	fprintf(stderr, "  -z          : run as external acl helper instead as a redirector\n");
	fprintf(stderr, "  -C file|all : create new .db files from urls/domain files\n");
	fprintf(stderr, "                specified in \"file\".\n");
	fprintf(stderr, "  -P          : do not go into emergency mode when an error with the \n");
	fprintf(stderr, "                blacklists is encountered.\n");

#ifdef USE_SYSLOG
	closelog();
#endif
	exit(1);
}
