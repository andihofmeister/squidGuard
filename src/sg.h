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

#ifndef SG_H
#define SG_H

#include "config.h"
#include "version.h"

#define MAX_BUF 12288

#define DEFAULT_LOGFILE "squidGuard.log"
#define WARNING_LOGFILE "squidGuard.log"
#define ERROR_LOGFILE   "squidGuard.error"

#ifndef DEFAULT_CONFIGFILE
#define DEFAULT_CONFIGFILE "/usr/local/squidGuard/squidGuard.conf"
#endif

#ifndef DEFAULT_LOGDIR
#define DEFAULT_LOGDIR "/usr/local/squidGuard/log"
#endif

#ifndef DEFAULT_DBHOME
#define DEFAULT_DBHOME "/usr/local/squidGuard/db"
#endif

void sgReadConfig(char *);
void freeAllLists(void);
void sgReloadConfig();


#endif
