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


%{

#include <stdio.h>

#include "sg.h"
#include "sgLog.h"
#include "sgMemory.h"
#include "sgRequestLog.h"

#include "sgAccessList.h"

#include "sgSourceList.h"
#include "sgStaticSource.h"
#include "sgGroup.h"
#include "sgLDAP.h"
#include "sgNetGroup.h"

#include "sgDestList.h"
#include "sgStaticDest.h"
#include "sgDomainList.h"
#include "sgUrlList.h"
#include "sgRegex.h"
#include "sgDNSBL.h"

#include "sgTimeMatch.h"
#include "sgSetting.h"

extern int lineno;

struct SourceList * curSrc = NULL;
struct AccessList * curAcl = NULL;
struct DestList   * curDest = NULL;
struct RegexList  * curExpr = NULL;

struct TimeMatch * curTimeMatch = NULL;
struct TimeMatchElement * curWM = NULL;
struct TimeMatchElement * curDM = NULL;

void yyerror(char *);
extern int yylex(void);

FILE *yyin, *yyout;
const char *configFile;

%}

%token ACL
%token ALLOW
%token ANONYMOUS
%token ANY
%token CHAR
%token DATE
%token DESTINATION
%token DNSBL
%token DOMAIN
%token DOMAINLIST
%token DVAL
%token DVALCRON
%token ELSE
%token END
%token ERRORREDIRECT
%token EXECCMD
%token EXECUSERLIST
%token EXPRESSIONLIST
%token GROUP
%token HOURLY
%token IP
%token IPLIST
%token LDAPIPSEARCH
%token LDAPUSERSEARCH
%token LOGFILE
%token NETGROUP
%token NEXT
%token NL
%token NONE
%token NUMBER
%token OUTSIDE
%token PASS
%token QUOTED_STRING
%token REDIRECT
%token REWRITE
%token SET
%token SOURCE
%token START_BRACKET
%token STOP_BRACKET
%token SUBST
%token TAG
%token TIME
%token TVAL
%token URLLIST
%token USER
%token USERLIST
%token VERBOSE
%token WEEKDAY
%token WEEKLY
%token WITHIN
%token WORD

%union {
	char			*string;
	char 			*tval;
	struct DestMatch	*dmatch;
	struct SourceMatch	*smatch;
	struct RequestLog	*logfile;
}

%type <string> WORD
%type <string> QUOTED_STRING
%type <string> STRING
%type <string> EXECCMD
%type <string> WEEKDAY
%type <string> NUMBER
%type <tval> TVAL
%type <string> DVAL
%type <string> DVALCRON
%type <string> CHAR
%type <string> SUBST
%type <string> date
%type <dmatch> dest_match
%type <smatch> source_match
%type <string> settingvalue
%type <logfile> logfile
%%

start: statements
;

STRING:		WORD | QUOTED_STRING ;

settingvalue:	WORD | QUOTED_STRING | NUMBER;

setting:	SET WORD settingvalue { setSetting($2, $3); sgFree($2); sgFree($3) } ;

start_block:	START_BRACKET;

stop_block:	STOP_BRACKET;

destination_block:
		destination start_block destination_contents stop_block ;

destination:	DESTINATION WORD { curDest = newDestList($2); sgFree($2); } ;

destination_contents:
		| destination_contents destination_content ;

destination_content:
		  dest_match      { addDestListMatch(curDest,$1); }
		| REDIRECT STRING { addDestListRedirect(curDest,$2);         sgFree($2); }
		| REWRITE STRING  { addDestListRewrite(curDest,$2);          sgFree($2); }
		| WITHIN WORD     { addDestListTime(curDest, $2, T_WITHIN);  sgFree($2); }
		| OUTSIDE WORD    { addDestListTime(curDest, $2, T_OUTSIDE); sgFree($2); }
		| logfile         { addDestListLog(curDest,$1); }
		;

dest_match:	  DOMAINLIST STRING  { $$ = newDestDomainListMatch(curDest->name,$2);  sgFree($2); }
		| DOMAINLIST '-'     { $$ = newDestDomainListMatch(curDest->name,NULL); }
		| URLLIST STRING     { $$ = newDestUrlListMatch(curDest->name,$2);     sgFree($2); }
		| URLLIST '-'        { $$ = newDestUrlListMatch(curDest->name,NULL); }
		| EXPRESSIONLIST '-' { $$ = newDestExpressionListMatch(curDest->name,NULL, NULL); }
		| EXPRESSIONLIST 'i' STRING { $$ = newDestExpressionListMatch(curDest->name,$3, "i"); sgFree($3); }
		| EXPRESSIONLIST STRING { $$ = newDestExpressionListMatch(curDest->name,$2, "n"); sgFree($2); }
		| DNSBL STRING       { $$ = newDNSBLMatch($2); sgFree($2); }
		;

source_block:	source start_block source_contents stop_block ;

source:		SOURCE WORD { curSrc = newSourceList($2); sgFree($2); };

source_contents:
		| source_contents source_content
		;

source_content:	  source_match { addSourceListMatch(curSrc, $1); }
		| source_static
		| WITHIN WORD  { addSourceListTime(curSrc, $2, T_WITHIN); sgFree($2); }
		| OUTSIDE WORD { addSourceListTime(curSrc, $2, T_OUTSIDE); sgFree($2); }
		| logfile      { addSourceListLog(curSrc, $1); }
		;

source_match:	  GROUP STRING          { $$ = newGroupMatch($2);        sgFree($2); }
		| NETGROUP STRING       { $$ = newNetgroupUserMatch($2); sgFree($2); }
		| LDAPUSERSEARCH STRING { $$ = newLDAPUserMatch($2);     sgFree($2); }
		| LDAPIPSEARCH STRING   { $$ = newLDAPIPMatch($2);       sgFree($2); }
		;

source_static:	  DOMAIN domain
		| USER users
		| IP ips
		| USERLIST STRING       { addUserListToSource(curSrc,$2);     sgFree($2); }
		| EXECUSERLIST EXECCMD  { addExecUserListToSource(curSrc,$2); sgFree($2); }
		| IPLIST STRING         { addIpListToSource(curSrc,$2);       sgFree($2); }
		;

domain:
		| domain STRING { /* sgSourceDomain($2); */ sgFree($2); }
		| domain ','
		;

ips:
		| ips STRING { addIpToSource(curSrc,$2); sgFree($2); }
		;

users:
		| users STRING { addUserToSource(curSrc,$2); sgFree($2); }
		;

acl_block:	ACL start_block acl_contents stop_block
		;

acl_contents:
		| acl_contents acl_content
		;

acl_content:	acl start_block access_contents stop_block
		;

acl:		  WORD { curAcl = newAccessList($1); sgFree($1); } aclwithin
		| ELSE { curAcl = newAccessList(curAcl->name); }   aclwithin
		;

aclwithin:
		| WITHIN WORD  { addAccessListTime(curAcl, $2, T_WITHIN);  sgFree($2); }
		| OUTSIDE WORD { addAccessListTime(curAcl, $2, T_OUTSIDE); sgFree($2); }
		;

access_contents:
		| access_contents access_content
		;

access_content:	  PASS access_dest { curAcl->terminal = 1; }
		| ALLOW            { curAcl->terminal = 1; }
		| NEXT access_dest { curAcl->terminal = 0; }
		| REWRITE WORD     { addAccessListRewrite(curAcl,$2); sgFree($2); }
		| REDIRECT STRING  { addAccessListRedirect(curAcl,$2); sgFree($2); }
		| logfile          { addAccessListLog(curAcl,$1); }
		| TAG WORD         { curAcl->tag = $2; }
		| WITHIN WORD      { addAccessListTime(curAcl, $2, T_WITHIN);  sgFree($2); }
		| OUTSIDE WORD     { addAccessListTime(curAcl, $2, T_OUTSIDE); sgFree($2); }
		;

logfile:	  LOGFILE ANONYMOUS STRING         { $$ = newRequestLog($3,1,0); sgFree($3); }
		| LOGFILE VERBOSE STRING           { $$ = newRequestLog($3,0,1); sgFree($3); }
		| LOGFILE ANONYMOUS VERBOSE STRING { $$ = newRequestLog($4,1,1); sgFree($4); }
		| LOGFILE VERBOSE ANONYMOUS STRING { $$ = newRequestLog($4,1,1); sgFree($4); }
		| LOGFILE STRING                   { $$ = newRequestLog($2,0,0); sgFree($2); }
		;


access_dest:
		| access_dest ANY      { addDestinationAccessCheck(curAcl,0,"any"); }
		| access_dest NONE     { addDestinationAccessCheck(curAcl,0,"none"); }
		| access_dest WORD     { addDestinationAccessCheck(curAcl,0,$2); sgFree($2); }
		| access_dest '!' WORD { addDestinationAccessCheck(curAcl,1,$3); sgFree($3); }
		;

rew:		REWRITE WORD { curExpr = newRewrite($2); sgFree($2); }
		;

rew_block:	rew start_block rew_contents stop_block
		;

rew_contents:
		| rew_contents rew_content
		;


rew_content:	  SUBST  { addRewriteExpression(curExpr, $1); sgFree($1); }
		| WITHIN WORD { /* sgRewriteTime($2, T_WITHIN); */ sgFree($2); }
		| OUTSIDE WORD { /* sgRewriteTime($2, T_OUTSIDE); */ sgFree($2); }
		;


time:		TIME WORD { curTimeMatch = newTimeMatch($2); sgFree($2); }
		;

time_block:	time start_block time_contents stop_block ;

time_contents:
		| time_contents time_spec
		;

time_spec:	  WEEKLY weekly
		| DATE date
		;

weekly:		  WORD    { curWM = addWeeklyElement(curTimeMatch, $1); sgFree($1); } wtime
		| WEEKDAY { curWM = addWeekdayElement(curTimeMatch,$1); sgFree($1); } wtime
		;

wtime:		  wtime TVAL '-' TVAL {
			curWM = dupWeeklyElement(curTimeMatch,curWM);
			setTimeValues(curWM,$2, $4);
			sgFree($2); sgFree($4);
		}
		| TVAL '-' TVAL { setTimeValues(curWM,$1, $3); sgFree($1); sgFree($3); }
		;

date:		  DVAL          { curDM = addDateElement(curTimeMatch,$1,NULL); sgFree($1); }            dtime
		| DVAL '-' DVAL { curDM = addDateElement(curTimeMatch,$1,$3);   sgFree($1); sgFree($3);} dtime
		| DVALCRON      { curDM = addCronDateElement(curTimeMatch,$1);  sgFree($1); }            dtime
		| DVALCRON      { curDM = addCronDateElement(curTimeMatch,$1);  sgFree($1); }
		;

dtime:		  dtime TVAL '-' TVAL {
			curDM = dupDateElement(curTimeMatch,curDM);
			setTimeValues(curDM,$2, $4);
			sgFree($2); sgFree($4);
		}
		| TVAL '-' TVAL { setTimeValues(curDM,$1, $3); sgFree($1); sgFree($3); }
		;


statements:
		| statements statement
		;

statement:	  setting
		| logfile { setDefaultRequestLog($1); }
		| REDIRECT STRING  { setDefaultRedirect($2); sgFree($2); }
		| ERRORREDIRECT STRING { setErrorRedirect($2); sgFree($2); }
		| acl_block
		| destination_block
		| source_block
		| rew_block
		| time_block
		| NL
		;

%%

void sgReadConfig(const char *file)
{
	char *defaultFile = DEFAULT_CONFIGFILE;
	lineno = 1;
	configFile = file;
	if (configFile == NULL)
		configFile = defaultFile;
	yyin = fopen(configFile, "r");
	if (yyin == NULL)
		sgLogFatal("can't open configfile  %s", configFile);

	makeStaticDestLists();

	(void)yyparse();

	fclose(yyin);
}

void freeAllLists() {
	freeAllAccessLists();
	freeDefaultRedirect();
	freeAllDestLists();
	freeAllSourceLists();
	freeAllRewrites();
	freeAllTimeMatches();
	freeAllRequestLogs();
	freeErrorRedirect();
}

void sgReloadConfig(const char *file)
{
	freeAllLists();
	sgReadConfig(file);
}

void yyerror(char *s)
{
	sgLogFatal("FATAL: %s in configfile %s line %d", s, configFile, lineno);
}

int yywrap()
{
	return 1;
}


