/*
  By accepting this notice, you agree to be bound by the following
  agreements:
 
  This software product, squidGuard, is copyrighted (C) 1998-2007
  by Christine Kronberg, Shalla Secure Services. All rights reserved.
 
  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License (version 2) as
  published by the Free Software Foundation.  It is distributed in the
  hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
  implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.  See the GNU General Public License (GPL) for more details.
 
  You should have received a copy of the GNU General Public License
  (GPL) along with this program.
*/


extern struct Setting *lastSetting ;
extern struct Setting *Setting;

extern struct Source *lastSource ;
extern struct Source *Source ;

extern struct Destination *lastDest ;
extern struct Destination *Dest ;

extern struct sgRewrite *lastRewrite;
extern struct sgRewrite *Rewrite;
extern struct sgRegExp *lastRewriteRegExec;

extern struct Time *lastTime;
extern struct Time *Time;

extern struct LogFile *globalLogFile;

extern struct LogFileStat *lastLogFileStat;
extern struct LogFileStat *LogFileStat;

extern struct TimeElement *lastTimeElement;
extern struct TimeElement *TimeElement;
extern int *TimeElementsEvents;

extern struct Acl *lastAcl ;
extern struct Acl *defaultAcl ;
extern struct Acl *Acl;
extern struct AclDest *lastAclDest;

extern struct sgRegExp *lastRegExpDest;

extern char *globalLogDir; /* from main.c */

extern struct Source *lastActiveSource;

extern int globalDebugTimeDelta;

extern int sig_hup;
extern int sig_alrm;

extern char **globalArgv;
extern char **globalEnvp;


