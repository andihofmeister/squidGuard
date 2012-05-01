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
#include "sg.h"
extern int globalDebug;
#ifdef USE_SYSLOG
extern int globalSyslog;
#endif

#ifdef HAVE_LIBLDAP
#define LDAP_DEPRECATED 1
#include "lber.h"
#include "ldap.h"
#endif

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif

#include "sgEx.h"

FILE *yyin, *yyout;
char *configFile;

int numTimeElements;
int *TimeElementsEvents;

static int time_switch = 0;
static int date_switch = 0;

int numSource = 0;

void sgSourceUserQuery(char *, char *, char *, char *);

void rfc1738_unescape(char *);
void
rfc1738_unescape(char *s)
{
	char hexnum[3];
	int i, j;       /* i is write, j is read */
	unsigned int x;

	for (i = j = 0; s[j]; i++, j++) {
		s[i] = s[j];
		if (s[i] != '%')
			continue;
		if (s[j + 1] == '%') { /* %% case */
			j++;
			continue;
		}
		if (s[j + 1] && s[j + 2]) {
			if (s[j + 1] == '0' && s[j + 2] == '0') { /* %00 case */
				j += 2;
				continue;
			}
			hexnum[0] = s[j + 1];
			hexnum[1] = s[j + 2];
			hexnum[2] = '\0';
			if (1 == sscanf(hexnum, "%x", &x)) {
				s[i] = (char)(0x0ff & x);
				j += 2;
			}
		}
	}
	s[i] = '\0';
}

%}

%union {
	char *	string;
	char *	tval;
	char *	dval;
	char *	dvalcron;
	int *	integer;
}

%token ACL
%token ALLOW
%token ANONYMOUS
%token CHAR
%token CIDR
%token CONTINIOUS
%token CONTINUE
%token DAILY
%token DATABASE
%token DATE
%token DBHOME
%token DESTINATION
%token DOMAIN
%token DOMAINLIST
%token DVAL
%token DVALCRON
%token ELSE
%token END
%token EXECCMD
%token EXECUSERLIST
%token EXPRESSIONLIST
%token GROUP
%token GROUPTTL
%token HOURLY
%token IP
%token IPADDR
%token IPCLASS
%token IPLIST
%token IPQUOTA
%token LDAPBINDDN
%token LDAPBINDPASS
%token LDAPCACHETIME
%token LDAPIPSEARCH
%token LDAPPROTOVER
%token LDAPUSERSEARCH
%token LOGDIR
%token LOGFILE
%token MINUTELY
%token MYSQLPASSWORD
%token MYSQLUSERNAME
%token NETGROUP
%token NEXT
%token NL
%token NUMBER
%token OUTSIDE
%token PASS
%token QUOTED_STRING
%token REDIRECT
%token REWRITE
%token SOURCE
%token SPORADIC
%token START_BRACKET
%token STOP_BRACKET
%token SUBST
%token SYSLOG
%token TIME
%token TVAL
%token URLLIST
%token USER
%token USERLIST
%token USERQUERY
%token USERQUOTA
%token VERBOSE
%token WEEKDAY
%token WEEKLY
%token WITHIN
%token WORD

%type <string> WORD
%type <string> QUOTED_STRING
%type <string> STRING
%type <string> EXECCMD
%type <string> WEEKDAY
%type <string> LDAPDNSTR
%type <string> NUMBER
%type <tval> TVAL
%type <string> DVAL
%type <string> DVALCRON
%type <string> CHAR
%type <string> SUBST
%type <string> IPADDR
%type <string> DBHOME LOGDIR
%type <string> CIDR
%type <string> IPCLASS
%type <string> acl_content
%type <string> acl
%type <string> dval
%type <string> dvalcron
%type <string> tval
%type <string> date
%type <string> ttime
%%

start: statements
;

STRING:		WORD | QUOTED_STRING
		;

LDAPDNSTR:	WORD | QUOTED_STRING
		;

dbhome:		DBHOME STRING { sgSetting("dbhome", $2); }
		;

sg_syslog:	SYSLOG STRING { sgSetting("syslog", $2); }
		;

logdir:		LOGDIR STRING { sgSetting("logdir", $2); }
		;

ldapcachetime:	LDAPCACHETIME NUMBER { sgSetting("ldapcachetime", $2); }
		;

ldapprotover:	LDAPPROTOVER NUMBER { sgSetting("ldapprotover", $2); }
		;

ldapbinddn:	LDAPBINDDN LDAPDNSTR { sgSetting("ldapbinddn", $2); }
		;

ldapbindpass:	LDAPBINDPASS STRING { sgSetting("ldapbindpass", $2); }
		;

mysqlusername:	MYSQLUSERNAME STRING { sgSetting("mysqlusername", $2); }
		;

mysqlpassword:	MYSQLPASSWORD STRING { sgSetting("mysqlpassword", $2); }
		;

mysqldb:	DATABASE STRING { sgSetting("mysqldb", $2); }
		;

groupttl:	GROUPTTL NUMBER { groupttl = atol($2); }
		;

start_block:	START_BRACKET
		;

stop_block:	STOP_BRACKET
		;

destination:	DESTINATION WORD { sgDest($2); }
		;

destination_block:
		destination start_block destination_contents stop_block
		{ sgDestEnd(); }
		;

destination_contents:
		| destination_contents destination_content
		;

destination_content:
		DOMAINLIST STRING { sgDestDomainList($2); }
		| DOMAINLIST '-' { sgDestDomainList(NULL); }
		| URLLIST STRING { sgDestUrlList($2); }
		| URLLIST '-'  { sgDestUrlList(NULL); }
		| EXPRESSIONLIST '-' { sgDestExpressionList(NULL, NULL); }
		| EXPRESSIONLIST 'i' STRING { sgDestExpressionList($3, "i"); }
		| EXPRESSIONLIST STRING { sgDestExpressionList($2, "n"); }
		| REDIRECT STRING { sgDestRedirect($2); }
		| REWRITE STRING { sgDestRewrite($2); }
		| WITHIN WORD { sgDestTime($2, WITHIN); }
		| OUTSIDE WORD { sgDestTime($2, OUTSIDE); }
		| LOGFILE ANONYMOUS STRING { sgLogFile(SG_BLOCK_DESTINATION, 1, 0, $3); }
		| LOGFILE VERBOSE STRING { sgLogFile(SG_BLOCK_DESTINATION, 0, 1, $3); }
		| LOGFILE ANONYMOUS VERBOSE STRING { sgLogFile(SG_BLOCK_DESTINATION, 1, 1, $4); }
		| LOGFILE VERBOSE ANONYMOUS STRING { sgLogFile(SG_BLOCK_DESTINATION, 1, 1, $4); }
		| LOGFILE STRING { sgLogFile(SG_BLOCK_DESTINATION, 0, 0, $2); }
		;

source:		SOURCE WORD { sgSource($2); }
		;

source_block:	source start_block source_contents stop_block { sgSourceEnd(); }
		;

source_contents:
		| source_contents source_content
		;

source_content:	DOMAIN domain
		| USER user
		| GROUP group
		| NETGROUP netgroup
		| USERLIST STRING { sgSourceUserList($2); }
		| USERQUERY WORD WORD WORD WORD { sgSourceUserQuery($2,$3,$4,$5); }
		| LDAPUSERSEARCH STRING { sgSourceLdapUserSearch($2); }
		| LDAPIPSEARCH STRING { sgSourceLdapIpSearch($2); }
		| EXECUSERLIST EXECCMD { sgSourceExecUserList($2); }
		| USERQUOTA NUMBER NUMBER HOURLY { sgSourceUserQuota($2, $3, "3600"); }
		| USERQUOTA NUMBER NUMBER DAILY { sgSourceUserQuota($2, $3, "86400"); }
		| USERQUOTA NUMBER NUMBER WEEKLY { sgSourceUserQuota($2, $3, "604800"); }
		| USERQUOTA NUMBER NUMBER NUMBER { sgSourceUserQuota($2, $3, $4); }
		| IP ips
		| IPLIST STRING { sgSourceIpList($2); }
		| WITHIN WORD { sgSourceTime($2, WITHIN); }
		| OUTSIDE WORD { sgSourceTime($2, OUTSIDE); }
		| LOGFILE ANONYMOUS STRING { sgLogFile(SG_BLOCK_SOURCE, 1, 0, $3); }
		| LOGFILE VERBOSE STRING { sgLogFile(SG_BLOCK_SOURCE, 0, 1, $3); }
		| LOGFILE ANONYMOUS VERBOSE STRING { sgLogFile(SG_BLOCK_SOURCE, 1, 1, $4); }
		| LOGFILE VERBOSE ANONYMOUS STRING { sgLogFile(SG_BLOCK_SOURCE, 1, 1, $4); }
		| LOGFILE STRING { sgLogFile(SG_BLOCK_SOURCE, 0, 0, $2); }
		| CONTINUE { lastSource->cont_search = 1; }
		;

domain:
		| domain STRING { sgSourceDomain($2); }
		| domain ','
		;

user:
		| user STRING { sgSourceUser($2); }
		| user ','
		;

group:
		| group STRING { sgSourceGroup($2); }
		| group ','
		;

netgroup:
		| netgroup STRING { sgSourceNetGroup($2); }
		| netgroup ','
		;

acl_block:	ACL start_block acl_contents stop_block
		;

acl_contents:
		| acl_contents acl_content
		;

acl:		WORD { sgAcl($1, NULL, 0); }
		| WORD WITHIN WORD { sgAcl($1, $3, WITHIN); }
		| WORD OUTSIDE WORD { sgAcl($1, $3, OUTSIDE); }
		;

acl_content:	acl start_block access_contents stop_block
		| acl start_block access_contents stop_block ELSE { sgAcl(NULL, NULL, ELSE); }
		start_block access_contents stop_block
		;

access_contents:
		| access_contents access_content
;

access_content:	PASS access_pass { }
		| ALLOW { sgAclSetValue("allow", 0, 0); }
		| NEXT access_next { }
		| REWRITE WORD { sgAclSetValue("rewrite", $2, 0); }
		| REDIRECT STRING { sgAclSetValue("redirect", $2, 0); }
		| LOGFILE ANONYMOUS STRING { sgLogFile(SG_BLOCK_ACL, 1, 0, $3); }
		| LOGFILE VERBOSE STRING { sgLogFile(SG_BLOCK_ACL, 0, 1, $3); }
		| LOGFILE ANONYMOUS VERBOSE STRING { sgLogFile(SG_BLOCK_ACL, 1, 1, $4); }
		| LOGFILE VERBOSE ANONYMOUS STRING { sgLogFile(SG_BLOCK_ACL, 1, 1, $4); }
		| LOGFILE STRING { sgLogFile(SG_BLOCK_ACL, 0, 0, $2); }
		;

access_pass:
		| access_pass WORD { sgAclSetValue("pass", $2, 1); }
		| access_pass '!' WORD { sgAclSetValue("pass", $3, 0); }
		| access_pass ','
		;

access_next:
		| access_next WORD { sgAclSetValue("next", $2, 1); }
		| access_next '!' WORD { sgAclSetValue("next", $3, 0); }
		| access_next ','
		;

cidr:		CIDR { sgIp($1); }
		;

ipclass:	IPCLASS { sgIp($1); }
		;

ips:
		| ips ip { sgIp("255.255.255.255"); sgSetIpType(SG_IPTYPE_HOST, NULL, 0); }
		| ips ip cidr { sgSetIpType(SG_IPTYPE_CIDR, NULL, 0); }
		| ips ip ipclass { sgSetIpType(SG_IPTYPE_CLASS, NULL, 0); }
		| ips ip '-' ip  { sgSetIpType(SG_IPTYPE_RANGE, NULL, 0); }
		| ips ','
		;

ip:		IPADDR { sgIp($1); }
		;

rew:		REWRITE WORD { sgRewrite($2); }
		;

rew_block:	rew start_block rew_contents stop_block
		;

rew_contents:
		| rew_contents rew_content
		;


rew_content:	SUBST  { sgRewriteSubstitute($1); }
		| WITHIN WORD { sgRewriteTime($2, WITHIN); }
		| OUTSIDE WORD { sgRewriteTime($2, OUTSIDE); }
		| LOGFILE ANONYMOUS STRING { sgLogFile(SG_BLOCK_REWRITE, 1, 0, $3); }
		| LOGFILE VERBOSE STRING { sgLogFile(SG_BLOCK_REWRITE, 0, 1, $3); }
		| LOGFILE ANONYMOUS VERBOSE STRING { sgLogFile(SG_BLOCK_REWRITE, 1, 1, $4); }
		| LOGFILE VERBOSE ANONYMOUS STRING { sgLogFile(SG_BLOCK_REWRITE, 1, 1, $4); }
		| LOGFILE STRING { sgLogFile(SG_BLOCK_REWRITE, 0, 0, $2); }
		;


time:		TIME WORD { sgTime($2); }
		;

time_block:	time start_block time_contents stop_block
		;

time_contents:
		| time_contents time_content
		;


time_content:	WEEKLY { sgTimeElementInit(); } WORD { sgTimeElementAdd($3, T_WEEKLY); } ttime
		| WEEKLY { sgTimeElementInit(); } WEEKDAY { sgTimeElementAdd($3, T_WEEKDAY); } ttime
		| DATE { sgTimeElementInit(); } date { sgTimeElementEnd(); }
		;

ttime:		ttime { sgTimeElementClone(); } tval '-' tval
		| tval '-' tval
		;

date:		dval ttime
		| dval
		| dval '-' dval ttime
		| dval '-' dval
		| dvalcron ttime
		| dvalcron
		;

dval:		DVAL { sgTimeElementAdd($1, T_DVAL); }
		;

tval:		TVAL { sgTimeElementAdd($1, T_TVAL); }
		;

dvalcron:	DVALCRON { sgTimeElementAdd($1, T_DVALCRON); }
		;

statements:
		| statements statement
		;

statement:	destination
		| source_block
		| destination_block
		| dbhome
		| logdir
		| groupttl
		| sg_syslog
		| ldapprotover
		| ldapbinddn
		| ldapbindpass
		| ldapcachetime
		| mysqlusername
		| mysqlpassword
		| mysqldb
		| acl_block
		| rew_block
		| time_block
		| NL
		;

%%

void sgReadConfig(char *file)
{
	char *defaultFile = DEFAULT_CONFIGFILE;
	lineno = 1;
	configFile = file;
	if (configFile == NULL)
		configFile = defaultFile;
	yyin = fopen(configFile, "r");
	if (yyin == NULL)
		sgLogFatal("%s: FATAL: can't open configfile  %s", progname, configFile);
	(void)yyparse();
	if (defaultAcl == NULL)
		sgLogFatal("%s: FATAL: default acl not defined in configfile  %s",
			   progname, configFile);
	fclose(yyin);
}


/*
 *
 * Logfile functions
 *
 */

void sgLogFile(int block, int anonymous, int verbose, char *file)
{
	void **v;
	char *name;
	struct LogFile *p;
	switch (block) {
	case (SG_BLOCK_DESTINATION):
		v = (void **)&lastDest->logfile;
		name = lastDest->name;
		break;
	case (SG_BLOCK_SOURCE):
		v = (void **)&lastSource->logfile;
		name = lastSource->name;
		break;
	case (SG_BLOCK_REWRITE):
		v = (void **)&lastRewrite->logfile;
		name = lastRewrite->name;
		break;
	case (SG_BLOCK_ACL):
		v = (void **)&lastAcl->logfile;
		name = lastAcl->name;
		if (strcmp(name, "default"))
			sgLogError("logfile not allowed in acl other than default");
		break;
	default:
		return;
	}
	if (*v == NULL) {
		p = sgMalloc(sizeof(struct LogFile));
		p->stat = sgLogFileStat(file);
		p->parent_name = name;
		p->parent_type = block;
		p->anonymous = anonymous;
		p->verbose = verbose;
		*v = p;
	} else {
		sgLogError("%s: redefine of logfile %s in line %d",
			   progname, file, lineno);
		return;
	}
}

struct LogFileStat *sgLogFileStat(char *file)
{
	struct LogFileStat *sg;
	struct stat s;
	char buf[MAX_BUF];
	FILE *fd;
	strncpy(buf, file, MAX_BUF);
	if (*file != '/') {
		if (globalLogDir == NULL)
			strncpy(buf, DEFAULT_LOGDIR, MAX_BUF);
		else
			strncpy(buf, globalLogDir, MAX_BUF);
		strcat(buf, "/");
		strcat(buf, file);
	}
	if ((fd = fopen(buf, "a")) == NULL) {
		sgLogError("%s: can't write to logfile %s", progname, buf);
		return NULL;
	}
	if (stat(buf, &s) != 0) {
		sgLogError("%s: can't stat logfile %s", progname, buf);
		return NULL;
	}
	if (LogFileStat == NULL) {
		sg = sgMalloc(sizeof(struct LogFileStat));
		sg->name = sgMalloc(strlen(buf) + 1);
		strcpy(sg->name, buf);
		sg->st_ino = s.st_ino;
		sg->st_dev = s.st_dev;
		sg->fd = fd;
		sg->next = NULL;
		LogFileStat = sg;
		lastLogFileStat = sg;
	} else {
		for (sg = LogFileStat; sg != NULL; sg = sg->next) {
			if (sg->st_ino == s.st_ino && sg->st_dev == s.st_dev) {
				fclose(fd);
				return sg;
			}
		}
		sg = sgMalloc(sizeof(struct LogFileStat));
		sg->name = sgMalloc(strlen(buf) + 1);
		strcpy(sg->name, buf);
		sg->st_ino = s.st_ino;
		sg->st_dev = s.st_dev;
		sg->fd = fd;
		sg->next = NULL;
		lastLogFileStat->next = sg;
		lastLogFileStat = sg;
	}
	return lastLogFileStat;
}
/*
 *
 * Source functions
 *
 */

void sgSource(char *source)
{
	struct Source *sp;
	if (Source != NULL) {
		if ((struct Source *)sgSourceFindName(source) != NULL)
			sgLogFatal("%s: source %s is defined in configfile %s",
				   progname, source, configFile);
	}
	sp = sgMalloc(sizeof(struct Source));
	sp->ip = NULL;
	sp->userDb = NULL;
	sp->domainDb = NULL;
	sp->active = 1;
	sp->within = 0;
	sp->cont_search = 0;
	sp->time = NULL;
	sp->userquota.seconds = 0;
	sp->userquota.renew = 0;
	sp->userquota.sporadic = 0;
#ifdef HAVE_LIBLDAP
	sp->ipDb = NULL;
	sp->ipquota.seconds = 0;
	sp->ipquota.renew = 0;
	sp->ipquota.sporadic = 0;
#endif
	sp->next = NULL;
	sp->logfile = NULL;
	sp->name = sgMalloc(strlen(source) + 1);
	strcpy(sp->name, source);

	if (Source == NULL) {
		Source = sp;
		lastSource = sp;
	} else {
		lastSource->next = sp;
		lastSource = sp;
	}
}

#ifdef HAVE_LIBLDAP
void sgSourceEnd()
{
	struct Source *s;

	s = lastSource;
	if (s->ip == NULL && s->domainDb == NULL && s->userDb == NULL
	    && s->grouplist == NULL
	    && s->netgrouplist == NULL
	    && s->ipDb == NULL
	    && s->ldapuserurlcount == 0 && s->ldapipurlcount == 0) {
		sgLogError("sourceblock %s missing active content, set inactive", s->name);
		s->time = NULL;
		s->active = 0;
	}
}
#else
void sgSourceEnd()
{
	struct Source *s;

	s = lastSource;
	if (s->ip == NULL && s->domainDb == NULL && s->userDb == NULL &&
	    s->grouplist == NULL && s->netgrouplist == NULL) {
		sgLogError("sourceblock %s missing active content, set inactive", s->name);
		s->time = NULL;
		s->active = 0;
	}
}
#endif

void sgSourceUser(char *user)
{
	struct Source *sp;
	char *lc;
	sp = lastSource;
	if (sp->userDb == NULL) {
		sp->userDb = sgMalloc(sizeof(struct sgDb));
		sp->userDb->type = SGDBTYPE_USERLIST;
		sgDbInit(sp->userDb, NULL);
	}
	for (lc = user; *lc != '\0'; lc++) /* convert username to lowercase chars */
		*lc = tolower(*lc);
	sgDbUpdate(sp->userDb, user, (char *)setuserinfo(),
		   sizeof(struct UserInfo));
	sgLogDebug("Added User: %s", user);
}

void sgSourceUserList(char *file)
{
	char *dbhome = NULL, *f;
	FILE *fd;
	char line[MAX_BUF];
	char *p, *c, *s, *lc;
	int l = 0;
	struct Source *sp;
	sp = lastSource;
	if (sp->userDb == NULL) {
		sp->userDb = sgMalloc(sizeof(struct sgDb));
		sp->userDb->type = SGDBTYPE_USERLIST;
		sgDbInit(sp->userDb, NULL);
	}
	dbhome = sgSettingGetValue("dbhome");
	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;
	if (file[0] == '/') {
		f = strdup(file);
	} else {
		f = sgMalloc(strlen(dbhome) + strlen(file) + 5);
		strcpy(f, dbhome);
		strcat(f, "/");
		strcat(f, file);
	}
	if ((fd = fopen(f, "r")) == NULL) {
		sgLogError("%s: can't open userlist %s: %s", progname, f, strerror(errno));
		return;
	}
	while (fgets(line, sizeof(line), fd) != NULL) {
		l++;
		if (*line == '#')
			continue;
		p = strchr(line, '\n');
		if (p != NULL && p != line) {
			if (*(p - 1) == '\r') /* removing ^M  */
				p--;
			*p = '\0';
		}
		c = strchr(line, '#');
		p = strtok(line, " \t,");
		if ((s = strchr(line, ':')) != NULL) {
			*s = '\0';
			for (lc = line; *lc != '\0'; lc++) /* convert username to lowercase chars */
				*lc = tolower(*lc);
			sgDbUpdate(sp->userDb, line, (char *)setuserinfo(),
				   sizeof(struct UserInfo));
		} else {
			do {
				if (c != NULL && p >= c)        /*find the comment */
					break;
				for (lc = p; *lc != '\0'; lc++) /* convert username to lowercase chars */
					*lc = tolower(*lc);
				sgDbUpdate(sp->userDb, p, (char *)setuserinfo(),
					   sizeof(struct UserInfo));
// DEBUG
				sgLogDebug("Added UserList source: %s", p);
			} while ((p = strtok(NULL, " \t,")) != NULL);
		}
	}
	fclose(fd);
}


/* MySQLsupport */
void sgSourceUserQuery(char *query, char * broke_1, char * broke_2, char * broke_4)
{
#ifdef HAVE_MYSQL
	char *dbhome = NULL, *f;
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW *row;
	char line[MAX_BUF];
	char *my_query, *my_user, *my_pass, *my_db;
	char *str = ";";
	int l = 0;
	struct Source *sp;
	sp = lastSource;
	if (sp->userDb == NULL) {
		sp->userDb = sgMalloc(sizeof(struct sgDb));
		sp->userDb->type = SGDBTYPE_USERLIST;
		sgDbInit(sp->userDb, NULL);
	}
	dbhome = sgSettingGetValue("dbhome");
	my_user = sgSettingGetValue("mysqlusername");
	my_pass = sgSettingGetValue("mysqlpassword");
	my_db = sgSettingGetValue("mysqldb");
	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;
	if (!(conn = mysql_init(0))) {
		sgLogError("%s: can't open userquery: mysql init", progname);
		return;
	}
	if (!mysql_real_connect(conn, "localhost", my_user, my_pass, my_db,
				0, NULL, 0)) {
		sgLogError("%s: can't open userquery: mysql connect", progname);
		return;
	}
	my_query = sgMalloc(strlen(query) + strlen(str) + 1);
	strcat(my_query, query);
	strcat(my_query, str);
	/* DEBUG:   sgLogError("%s: TEST: MySQL Query %s",progname,my_query);  */
	if (mysql_query(conn, my_query)) {
		sgLogError("%s: can't open userquery: mysql query", progname);
		return;
	}
	res = mysql_use_result(conn);
	while (row = mysql_fetch_row(res)) {
		strncpy(line, row[0], sizeof(line) - 1);
		l++;
		sgDbUpdate(sp->userDb, line, (char *)setuserinfo(), sizeof(struct UserInfo));
		sgLogDebug("Added MySQL source: %s", line);
	}
	mysql_free_result(res);
	mysql_close(conn);
#else
	sgLogFatal("This SquidGuard has not been compiled with database support");
#endif
}


/* LDAP Support */
void sgSourceLdapUserSearch(char *url)
{
#ifdef HAVE_LIBLDAP
	struct Source *sp;
	sp = lastSource;

/*  DEBUG
 * sgLogDebug("sgSourceLdapUserSearch called with: %s", url);
 */

	if (!ldap_is_ldap_url(url)) {
		sgLogError("%s: can't parse LDAP url %s", progname, url);
		return;
	}

	/* looks ok, add the url to the source object url array */
	sp->ldapuserurls = (char **)sgRealloc(sp->ldapuserurls,
					      sizeof(char *) * (sp->ldapuserurlcount + 1));
	sp->ldapuserurls[sp->ldapuserurlcount] = sgMalloc(strlen(url) + 1);
	strcpy(sp->ldapuserurls[sp->ldapuserurlcount], url);
	sp->ldapuserurlcount++;

	/* create a userDb if it doesn't exist, since we'll need it later
	 * for caching */
	if (sp->userDb == NULL) {
		sp->userDb = sgMalloc(sizeof(struct sgDb));
		sp->userDb->type = SGDBTYPE_USERLIST;
		sgDbInit(sp->userDb, NULL);
	}
#else
	sgLogFatal("This SquidGuard has not been compiled with LDAP support");
#endif
}
void sgSourceLdapIpSearch(char *url)
{
#ifdef HAVE_LIBLDAP
	struct Source *sp;
	sp = lastSource;

	sgLogDebug("DEBUG: sgSourceLdapIpSearch called with: %s", url);

	if (!ldap_is_ldap_url(url)) {
		sgLogError("%s: can't parse LDAP url %s", progname, url);
		return;
	}

	/* looks ok, add the url to the source object url array */
	sp->ldapipurls = (char **)sgRealloc(sp->ldapipurls,
					    sizeof(char *) * (sp->ldapipurlcount + 1));
	sp->ldapipurls[sp->ldapipurlcount] = sgMalloc(strlen(url) + 1);
	strcpy(sp->ldapipurls[sp->ldapipurlcount], url);
	sp->ldapipurlcount++;

	/* create a ipDb if it doesn't exist, since we'll need it later
	 * for caching */
	if (sp->ipDb == NULL) {
		sp->ipDb = sgMalloc(sizeof(struct sgDb));
		sp->ipDb->type = SGDBTYPE_USERLIST;
		sgDbInit(sp->ipDb, NULL);
	}
#else
	sgLogFatal("This SquidGuard has not been compiled with LDAP support");
#endif
}

void sgSourceExecUserList(char *cmd)
{
	FILE *pInput;
	char buffer[100];
	struct Source *sp;
	char *lc;
	sp = lastSource;
	if (sp->userDb == NULL) {
		sp->userDb = sgMalloc(sizeof(struct sgDb));
		sp->userDb->type = SGDBTYPE_USERLIST;
		sgDbInit(sp->userDb, NULL);
	}

/*  DEBUG
 * sgLogDebug("sgSourceExecUserList called with: %s", cmd);
 */

	pInput = popen(cmd, "r");
	if (pInput == NULL) {
		sgLogError("%s: Unable to run execuserlist command: %s", progname, cmd);
		return;
	}

	while (fgets(buffer, sizeof(buffer), pInput) != NULL) {
		char *sc;
		/* skip leading whitespace */
		for (sc = buffer; *sc != '\0' && isspace(*sc); sc++)
			;
		/* convert username to lowercase */
		for (lc = sc; *lc != '\0'; lc++)
			*lc = tolower(*lc);
		/* remove newline and trailing whitespace */
		while (lc >= sc && (*lc == '\0' || isspace(*lc)))
			*lc-- = '\0';
		if (lc >= sc) {
			sgDbUpdate(sp->userDb, sc, (char *)setuserinfo(),
				   sizeof(struct UserInfo));
			sgLogDebug("Added exec source: %s", sc);
		}
	}

	pclose(pInput);
}



void sgSourceUserQuota(char *seconds, char *sporadic, char *renew)
{
	int s;
	struct UserQuota *uq;
	struct Source *sp;
	sp = lastSource;
	uq = &sp->userquota;
	s = atoi(seconds);
	if (s <= 0)
		sgLogError("Userquota seconds sporadic hourly|daily|weekly");
	uq->seconds = s;
	s = atoi(sporadic);
	if (s <= 0)
		sgLogError("Userquota seconds sporadic hourly|daily|weekly");
	uq->sporadic = s;
	s = atoi(renew);
	if (s <= 0)
		sgLogError("Userquota seconds sporadic hourly|daily|weekly");
	uq->renew = s;
}


void sgSourceDomain(char *domain)
{
	struct Source *sp;
	sp = lastSource;
	if (sp->domainDb == NULL) {
		sp->domainDb = sgMalloc(sizeof(struct sgDb));
		sp->domainDb->type = SGDBTYPE_DOMAINLIST;
		sgDbInit(sp->domainDb, NULL);
	}
	sgDbUpdate(sp->domainDb, domain, NULL, 0);
}

void sgSourceTime(char *name, int within)
{
	struct Time *time = NULL;
	struct Source *sp;
	sp = lastSource;
	if ((time = sgTimeFindName(name)) == NULL)
		sgLogFatal("%s: FATAL: Time %s is not defined in configfile %s",
			   progname, name, configFile);
	sp->within = within;
	sp->time = time;
}

struct Source *sgSourceFindName(char *name)
{
	struct Source *p;
	for (p = Source; p != NULL; p = p->next)
		if (!strcmp(name, p->name))
			return p;
	return NULL;
}

void sgSourceIpList(char *file)
{
	char *dbhome = NULL, *f;
	FILE *fd;
	char line[MAX_BUF];
	char *p, *c, *cidr;
	int i, l = 0;
	dbhome = sgSettingGetValue("dbhome");
	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;
	if (file[0] == '/') {
		f = strdup(file);
	} else {
		f = sgMalloc(strlen(dbhome) + strlen(file) + 5);
		strcpy(f, dbhome);
		strcat(f, "/");
		strcat(f, file);
	}
	if ((fd = fopen(f, "r")) == NULL) {
		sgLogError("%s: can't open iplist %s: %s", progname, f, strerror(errno));
		return;
	}
	sgLogDebug("init iplist %s", f);
	while (fgets(line, sizeof(line), fd) != NULL) {
		l++;
		if (*line == '#')
			continue;
		p = strchr(line, '\n');
		if (p != NULL && p != line) {
			if (*(p - 1) == '\r') /* removing ^M  */
				p--;
			*p = '\0';
		}
		c = strchr(line, '#');
		p = strtok(line, " \t,");
		do {
			if (c != NULL && p >= c) /*find the comment */
				break;
			i = strspn(p, ".0123456789/-");
			if (i == 0)
				break;
			*(p + i) = '\0';
			if ((cidr = strchr(p, '/')) != NULL) {
				*cidr = '\0';
				cidr++;
				sgIp(p);
				sgIp(cidr);
				if (strchr(cidr, '.') == NULL)
					sgSetIpType(SG_IPTYPE_CIDR, f, l);
				else
					sgSetIpType(SG_IPTYPE_CLASS, f, l);
			} else if ((cidr = strchr(p, '-')) != NULL) {
				*cidr = '\0';
				cidr++;
				sgIp(p);
				sgIp(cidr);
				sgSetIpType(SG_IPTYPE_RANGE, f, l);
			} else {
				sgIp(p);
				sgIp(strdup("255.255.255.255"));
				sgSetIpType(SG_IPTYPE_HOST, f, l);
			}
		} while ((p = strtok(NULL, " \t,")) != NULL);
	}
	fclose(fd);
}

/*
 *
 *
 */

struct Source *sgFindSource(struct Source *bsrc, char *net, char *ident, char *domain)
{
/* DEBUG
 * sgLogDebug("DEBUG: sgfindsource  called with: %s", net);
 */
	struct Source *s;
	struct Ip *ip;
	int foundip, founduser, founddomain, unblockeduser;
	unsigned long i, octet = 0, *op;
	struct UserInfo *userquota;
	char *dotnet = NULL;
#ifdef HAVE_LIBLDAP
	int unblockedip;
	struct IpInfo *ipquota;
#endif
	if (net != NULL) {
		dotnet = sgMalloc(strlen(net) + 1);
		strcpy(dotnet, net);
		op = sgConvDot(net);
		if (op != NULL)
			octet = *op;
	}
	for (s = bsrc; s != NULL; s = s->next) {
		foundip = founduser = founddomain = 0;
		unblockeduser = 1;
		if (s->active == 0)
			continue;
		if (s->ip != NULL) {
			if (net == NULL) {
				foundip = 0;
			} else {
				for (ip = s->ip; ip != NULL; ip = ip->next) {
					if (ip->net_is_set == 0)
						continue;
					if (ip->type == SG_IPTYPE_RANGE) {
						if (octet >= ip->net && octet <= ip->mask) {
							foundip = 1;
							break;
						}
					} else { /* CIDR or HOST */
						i = octet & ip->mask;
						if (i == ip->net) {
							foundip = 1;
							break;
						}
					}
				}
			}
		} else
#ifdef HAVE_LIBLDAP
// debut ip
		if (s->ipDb != NULL) {
			if (dotnet == NULL) {
				foundip = 0;
			} else {
//        rfc1738_unescape(dotnet);
				if (sgFindIp(s, dotnet, &ipquota)) {
					foundip = 1;
					unblockedip = 1;
					if (s->ipquota.seconds != 0) {
						time_t t = time(NULL) + globalDebugTimeDelta;
						sgLogDebug("status %d time %d lasttime %d consumed %d", ipquota->status, ipquota->time, ipquota->last, ipquota->consumed);
						sgLogDebug("renew %d seconds %d", s->ipquota.renew, s->ipquota.seconds);
						if (ipquota->status == 0) { //first time
							ipquota->status = 1;
							ipquota->time = t;
							ipquota->last = t;
							sgLogDebug("ip %s first time %d", dotnet, ipquota->time);
						} else if (ipquota->status == 1) {
							sgLogDebug("ip %s other time %d %d", dotnet, ipquota->time, t);
							if (s->ipquota.sporadic > 0) {
								if (t - ipquota->last < s->ipquota.sporadic) {
									ipquota->consumed += t - ipquota->last;
									ipquota->time = t;
								}
								if (ipquota->consumed > s->ipquota.seconds) {
									ipquota->status = 2; // block this ip, time is up
									unblockedip = 0;
								}
								ipquota->last = t;
								sgLogDebug("ip %s consumed %d %d", dotnet, ipquota->consumed, ipquota->last);
							} else if (ipquota->time + s->ipquota.seconds < t) {
								sgLogDebug("time is up ip %s blocket", net);
								ipquota->status = 2; // block this ip, time is up
								unblockedip = 0;
							}
						} else {
							sgLogDebug("ip %s blocked %d %d %d %d", dotnet, ipquota->status, ipquota->time, t, (ipquota->time + s->ipquota.renew) - t);
							if (ipquota->time + s->ipquota.renew < t) { // new chance
								sgLogDebug("ip %s new chance", net);
								unblockedip = 1;
								ipquota->status = 1;
								ipquota->time = t;
								ipquota->consumed = 0;
							} else {
								unblockedip = 0;
							}
						}
						sgDbUpdate(s->ipDb, dotnet, (void *)ipquota,
							   sizeof(struct IpInfo));
					}
				}
			}
		} else
#endif
		{       //fin ip
			foundip = 1;
		}
		if (s->userDb != NULL || s->grouplist != NULL || s->netgrouplist != NULL) {
			if (*ident == '\0') {
				founduser = 0;
			} else {
#ifdef HAVE_LIBLDAP
				if (sgFindUser(s, ident, &userquota)) {
#else
				rfc1738_unescape(ident);
				if (s->userDb != NULL && defined(s->userDb, ident, (char **)&userquota) == 1) {
#endif
					founduser = 1;
					unblockeduser = 1;
					if (s->userquota.seconds != 0) {
						time_t t = time(NULL) + globalDebugTimeDelta;
						//sgLogError("status %d time %d lasttime %d consumed %d", userquota->status, userquota->time, userquota->last, userquota->consumed);
						//sgLogError("renew %d seconds %d", s->userquota.renew, s->userquota.seconds);
						if (userquota->status == 0) { //first time
							userquota->status = 1;
							userquota->time = t;
							userquota->last = t;
							//sgLogError("user %s first time %d", ident, userquota->time);
						} else if (userquota->status == 1) {
							//sgLogError("user %s other time %d %d",ident,userquota->time,t);
							if (s->userquota.sporadic > 0) {
								if (t - userquota->last < s->userquota.sporadic) {
									userquota->consumed += t - userquota->last;
									userquota->time = t;
								}
								if (userquota->consumed > s->userquota.seconds) {
									userquota->status = 2; // block this user, time is up
									unblockeduser = 0;
								}
								userquota->last = t;
								//sgLogError("user %s consumed %d %d",ident,userquota->consumed, userquota->last);
							} else if (userquota->time + s->userquota.seconds < t) {
								sgLogDebug("time is up user %s blocked", ident);
								userquota->status = 2; // block this user, time is up
								unblockeduser = 0;
							}
						} else {
							//sgLogError("user %s blocked %d %d %d %d", ident, userquota->status, userquota->time, t, (userquota->time + s->userquota.renew) - t);
							if (userquota->time + s->userquota.renew < t) { // new chance
								//sgLogError("user %s new chance", ident);
								unblockeduser = 1;
								userquota->status = 1;
								userquota->time = t;
								userquota->consumed = 0;
							} else {
								unblockeduser = 0;
							}
						}
						sgDbUpdate(s->userDb, ident, (void *)userquota,
							   sizeof(struct UserInfo));
					}
				}
			}
			if (founduser == 0)
				founduser = groupmember(s->grouplist, ident, s->name);
			if (founduser == 0)
				founduser = sgCheckNetGroup(s->netgrouplist, ident, s->name);
		} else {
			founduser = 1;
		}
		if (s->domainDb != NULL) {
			if (*domain == '\0')
				founddomain = 0;
			else
				if (defined(s->domainDb, domain, (char **)NULL) == 1)
					founddomain = 1;
		} else {
			founddomain = 1;
		}
		if (founduser && foundip && founddomain) {
			if (unblockeduser) {
				return s;
			} else {
				lastActiveSource = s;
				return NULL;
			}
		}
	}
	return NULL;
}



/*destination block funtions */

void sgDest(char *dest)
{
	struct Destination *sp;
	if (Dest != NULL) {
		if ((struct Destination *)sgDestFindName(dest) != NULL)
			sgLogFatal("%s: destination %s is defined in configfile %s",
				   progname, dest, configFile);
	}
	sp = sgMalloc(sizeof(struct Destination));
	sp->domainlist = NULL;
	sp->urllist = NULL;
	sp->expressionlist = NULL;
	sp->redirect = NULL;
	sp->rewrite = NULL;
	sp->active = 1;
	sp->time = NULL;
	sp->within = 0;
	sp->logfile = NULL;
	sp->next = NULL;
	sp->name = sgMalloc(strlen(dest) + 1);
	strcpy(sp->name, dest);

	if (Dest == NULL) {
		Dest = sp;
		lastDest = sp;
	} else {
		lastDest->next = sp;
		lastDest = sp;
	}
}

void sgDestEnd()
{
	struct Destination *d;

	d = lastDest;
	if (d->domainlist == NULL && d->urllist == NULL && d->expressionlist == NULL
	    && d->redirect == NULL && d->rewrite == NULL) {
		sgLogError("destblock %s missing active content, set inactive", d->name);
		d->time = NULL;
		d->active = 0;
	}
}

void sgDestDomainList(char *domainlist)
{
	struct Destination *sp;
	char *dbhome = NULL, *dl = domainlist, *name;
	dbhome = sgSettingGetValue("dbhome");
	sp = lastDest;
	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;
	if (domainlist == NULL) {
		name = sp->name;
		dl = sgMalloc(strlen("/dest/") + strlen(name) + strlen("/domainlist"));
		strcpy(dl, "/dest/");
		strcat(dl, name);
		strcat(dl, "/domainlist");
		sp->domainlist = sgMalloc(strlen(dbhome) + strlen("/") + strlen(dl) + 4);
		strcpy(sp->domainlist, dbhome);
		strcat(sp->domainlist, "/");
		strcat(sp->domainlist, dl);
		sgFree(dl);
	} else {
		if (domainlist[0] == '/') {
			sp->domainlist = strdup(domainlist);
		} else {
			sp->domainlist = sgMalloc(strlen(dbhome) + strlen("/") + strlen(domainlist) + 4);
			strcpy(sp->domainlist, dbhome);
			strcat(sp->domainlist, "/");
			strcat(sp->domainlist, domainlist);
		}
	}
	sp->domainlistDb = sgMalloc(sizeof(struct sgDb));
	sp->domainlistDb->type = SGDBTYPE_DOMAINLIST;
	sgLogDebug("init domainlist %s", sp->domainlist);
	sgDbInit(sp->domainlistDb, sp->domainlist);
	if (sp->domainlistDb->entries == 0) { /* empty database */
		sgLogDebug("domainlist empty, removed from memory");
		sgFree(sp->domainlistDb);
		sp->domainlistDb = NULL;
	}
}

void sgDestUrlList(char *urllist)
{
	struct Destination *sp;
	char *dbhome = NULL, *dl = urllist, *name;
	dbhome = sgSettingGetValue("dbhome");
	sp = lastDest;
	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;
	if (urllist == NULL) {
		name = sp->name;
		dl = sgMalloc(strlen("/dest/") + strlen(name) + strlen("/urllist"));
		strcpy(dl, "/dest/");
		strcat(dl, name);
		strcat(dl, "/urllist");
		sp->urllist = sgMalloc(strlen(dbhome) + strlen("/") + strlen(dl) + 4);
		strcpy(sp->urllist, dbhome);
		strcat(sp->urllist, "/");
		strcat(sp->urllist, dl);
		sgFree(dl);
	} else {
		if (urllist[0] == '/') {
			sp->urllist = strdup(urllist);
		} else {
			sp->urllist = sgMalloc(strlen(dbhome) + strlen("/") + strlen(urllist) + 4);
			strcpy(sp->urllist, dbhome);
			strcat(sp->urllist, "/");
			strcat(sp->urllist, urllist);
		}
	}
	sp->urllistDb = sgMalloc(sizeof(struct sgDb));
	sp->urllistDb->type = SGDBTYPE_URLLIST;
	sgLogDebug("init urllist %s", sp->urllist);
	sgDbInit(sp->urllistDb, sp->urllist);
	if (sp->urllistDb->entries == 0) { /* empty database */
		sgLogDebug("urllist empty, removed from memory");
		sgFree(sp->urllistDb);
		sp->urllistDb = NULL;
	}
}

void sgDestExpressionList(char *exprlist, char *chcase)
{
	FILE *fp;
	char buf[MAX_BUF], errbuf[256];
	struct Destination *sp;
	struct sgRegExp *regexp;
	char *dbhome = NULL, *dl = exprlist, *name, *p;
	int flags = REG_EXTENDED;
	dbhome = sgSettingGetValue("dbhome");
	sp = lastDest;
	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;
	if (exprlist == NULL) {
		name = sp->name;
		dl = sgMalloc(strlen("/dest/") + strlen(name) + strlen("/expressionlist"));
		strcpy(dl, "/dest/");
		strcat(dl, name);
		strcat(dl, "/expressionlist");
		flags |= REG_ICASE; /* default case insensitive */
		sp->expressionlist = sgMalloc(strlen(dbhome) + strlen(dl) + 10);
		strcpy(sp->expressionlist, dbhome);
		strcat(sp->expressionlist, "/");
		strcat(sp->expressionlist, dl);
		sgFree(dl);
	} else {
		if (exprlist[0] == '/') {
			sp->expressionlist = strdup(exprlist);
		} else {
			sp->expressionlist = sgMalloc(strlen(dbhome) + strlen("/") + strlen(exprlist) + 4);
			strcpy(sp->expressionlist, dbhome);
			strcat(sp->expressionlist, "/");
			strcat(sp->expressionlist, exprlist);
		}
		if (strncmp(chcase, "c", 1))
			flags |= REG_ICASE;  /* set case insensitive */
	}
	sgLogDebug("init expressionlist %s", sp->expressionlist);
	if ((fp = fopen(sp->expressionlist, "r")) == NULL)
		sgLogFatal("%s: %s", sp->expressionlist, strerror(errno));
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		p = (char *)strchr(buf, '\n');
		if (p != NULL && p != buf) {
			if (*(p - 1) == '\r') /* removing ^M  */
				p--;
			*p = '\0';
		}
		regexp = sgNewPatternBuffer(buf, flags);
		if (regexp->error) {
			regerror(regexp->error, regexp->compiled, errbuf, sizeof(errbuf));
			sgLogError("%s: %s", sp->expressionlist, strerror(errno));
		}
		if (lastDest->regExp == NULL) {
			lastDest->regExp = regexp;
			lastRegExpDest = regexp;
		} else {
			lastRegExpDest->next = regexp;
			lastRegExpDest = regexp;
		}
	}
	fclose(fp);
}

void sgDestRedirect(char *value)
{
	struct Destination *sp;
	sp = lastDest;
	sp->redirect = sgMalloc(strlen(value) + 1);
	strcpy(sp->redirect, value);
}

void sgDestRewrite(char *value)
{
	struct sgRewrite *rewrite = NULL;
	struct Destination *sp;

	sp = lastDest;
	if ((rewrite = sgRewriteFindName(value)) == NULL)
		sgLogFatal("%s: FATAL: Rewrite %s is not defined in configfile %s",
			   progname, value, configFile);
	sp->rewrite = rewrite;
}

int sgRegExpMatch(struct sgRegExp *regexp, char *str)
{
	struct sgRegExp *rp;
	static char errbuf[256];
	int error;
	for (rp = regexp; rp != NULL; rp = rp->next) {
		error = regexec(rp->compiled, str, 0, 0, 0);
		if (error != 0 && error != REG_NOMATCH) {
			regerror(error, rp->compiled, errbuf, sizeof(errbuf));
			sgLogError("Error in regex %30.30s %-60.60s  %d %s\n", rp->pattern, str, error, errbuf);
		}
		if (error == 0) /* match */
			return 1;
	}
	return 0;
}

void sgDestTime(char *name, int within)
{
	struct Time *time = NULL;
	struct Destination *sp;
	sp = lastDest;
	if ((time = sgTimeFindName(name)) == NULL)
		sgLogFatal("%s: FATAL: Time %s is not defined in configfile %s",
			   progname, name, configFile);
	sp->within = within;
	sp->time = time;
}

struct Destination *sgDestFindName(char *name)
{
	struct Destination *p;
	for (p = Dest; p != NULL; p = p->next)
		if (!strcmp(name, p->name))
			return p;
	return NULL;
}

/*
 * Setting functions
 */


void sgSetting(char *name, char *value)
{
	struct Setting *sp;
	if (Setting != NULL)
		if ((struct Setting *)sgSettingFindName(name) != NULL)
			sgLogFatal("FATAL: %s: setting %s is defined in configfile %s", progname, name, configFile);
	sp = sgMalloc(sizeof(struct Setting));

	sp->name = strdup(name);
	sp->value = strdup(value);

// DEBUG
	if (strcmp(name, "ldapbindpass") == 0 || strcmp(name, "mysqlpassword") == 0)
		sgLogDebug("INFO: New setting: %s: ***************", name);
	else
		sgLogDebug("INFO: New setting: %s: %s", name, value);

	if (Setting == NULL) {
		Setting = sp;
		lastSetting = sp;
	} else {
		lastSetting->next = sp;
		lastSetting = sp;
	}
	if (!strcmp(name, "logdir"))
		globalLogDir = strdup(value);

#ifdef USE_SYSLOG
	if (!strcmp(name, "syslog"))
		sgSyslogSetting(value);

#endif
}

#ifdef USE_SYSLOG
void sgSyslogSetting(char *value)
{
	if (strcmp(value, "enable") == 0) {
		//printf(">> enable syslog option\n");
		globalSyslog = 1;
	} else if (strcmp(value, "disable") == 0) {
		//printf(">> disable syslog option \n");
		globalSyslog = 0;
	} else {
		printf("ERROR: Invalid syslog option in %s line %d. Syslog will not be used. See logfile for informations. \n", configFile, lineno);
		globalSyslog = 0;
		sgLogError("ERROR: Invalid syslog option in %s line %d. Syslog will not be used. See logfile for informations. \n", configFile, lineno);
	}
}
#endif


struct Setting *sgSettingFindName(char *name)
{
	struct Setting *p;
	for (p = Setting; p != NULL; p = p->next)
		if (!strcmp(name, p->name))
			return p;
	return NULL;
}


char *sgSettingGetValue(char *name)
{
	struct Setting *p;
	p = sgSettingFindName(name);
	if (p != NULL)
		return p->value;
	return NULL;
}


/*
 *
 * sgRewrite function
 *
 */

void sgRewrite(char *rewrite)
{
	struct sgRewrite *rew;
	if (Rewrite != NULL) {
		if ((struct sgRewrite *)sgRewriteFindName(rewrite) != NULL)
			sgLogFatal("%s: rewrite %s is defined in configfile %s",
				   progname, rewrite, configFile);
	}
	rew = sgMalloc(sizeof(struct sgRewrite));
	rew->name = strdup(rewrite);
	rew->rewrite = NULL;
	rew->logfile = NULL;
	rew->time = NULL;
	rew->active = 1;
	rew->within = 0;
	rew->next = NULL;

	if (Rewrite == NULL) {
		Rewrite = rew;
		lastRewrite = rew;
	} else {
		lastRewrite->next = rew;
		lastRewrite = rew;
	}
}

void sgRewriteTime(char *name, int within)
{
	struct Time *time = NULL;
	struct sgRewrite *sp;
	sp = lastRewrite;
	if ((time = sgTimeFindName(name)) == NULL)
		sgLogFatal("%s: FATAL: Time %s is not defined in configfile %s",
			   progname, name, configFile);
	sp->within = within;
	sp->time = time;
}

void sgRewriteSubstitute(char *string)
{
	char *pattern, *subst = NULL, *p;
	int flags = REG_EXTENDED;
	int global = 0;
	char *httpcode = NULL;
	struct sgRegExp *regexp;
	char errbuf[256];
	pattern = string + 2; /* skipping s@ */
	p = pattern;
	while ((p = strchr(p, '@')) != NULL) {
		if (*(p - 1) != '\\') {
			*p = '\0';
			subst = p + 1;
			break;
		}
		p++;
	}
	p = strrchr(subst, '@');
	while (p != NULL && *p != '\0') {
		if (*p == 'r')
			httpcode = REDIRECT_TEMPORARILY;
		if (*p == 'R')
			httpcode = REDIRECT_PERMANENT;
		if (*p == 'i' || *p == 'I')
			flags |= REG_ICASE;
		if (*p == 'g')
			global = 1;
		*p = '\0'; /*removes @i from string */
		p++;
	}
	regexp = sgNewPatternBuffer(pattern, flags);
	if (regexp->error) {
		regerror(regexp->error, regexp->compiled, errbuf, sizeof(errbuf));
		sgLogError("Error in regexp %s: %s", pattern, errbuf);
	} else {
		regexp->substitute = strdup(subst);
	}
	if (lastRewrite->rewrite == NULL)
		lastRewrite->rewrite = regexp;
	else
		lastRewriteRegExec->next = regexp;
	regexp->httpcode = httpcode;
	regexp->global = global;
	lastRewriteRegExec = regexp;
}

char *sgRewriteExpression(struct sgRewrite *rewrite, char *subst)
{
	char *result = NULL;
	result = sgRegExpSubst(rewrite->rewrite, subst);
	return result;
}

struct sgRewrite *sgRewriteFindName(char *name)
{
	struct sgRewrite *p;
	for (p = Rewrite; p != NULL; p = p->next)
		if (!strcmp(name, p->name))
			return p;
	return NULL;
}



/*
 * Time functions
 */

void sgTime(char *name)
{
	struct Time *t;
	if (Time != NULL) {
		if ((struct Time *)sgTimeFindName(name) != NULL)
			sgLogFatal("%s: time %s is defined in configfile %s",
				   progname, name, configFile);
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
			sgLogFatal("%s: FATAL: time formaterror in %s line %d",
				   progname, configFile, lineno);
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
			sgLogFatal("%s: FATAL: date formaterror in %s line %d",
				   progname, configFile, lineno);
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
				sgLogFatal("%s: FATAL: weekday formaterror in %s line %d",
					   progname, configFile, lineno);
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

int sgTimeCmp(const int *a, const int *b)
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

int sgTimeCheck(struct tm *lt, time_t t)
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

void sgTimeSetAcl()
{
	struct Acl *acl = defaultAcl;
	struct Destination *d;
	struct Source *s;
	struct sgRewrite *rew;

	for (acl = Acl; acl != NULL; acl = acl->next) {
		if (acl->time != NULL) {
			acl->active = acl->time->active;
			if (acl->within == OUTSIDE) {
				if (acl->active)
					acl->active = 0;
				else
					acl->active = 1;
			}
			if (acl->next != NULL && acl->next->within == ELSE) {
				if (acl->active == 0)
					acl->next->active = 1;
				else
					acl->next->active = 0;
			}
		}
	}
	for (d = Dest; d != NULL; d = d->next) {
		if (d->time != NULL) {
			d->active = d->time->active;
			if (d->within == OUTSIDE) {
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
			if (s->within == OUTSIDE) {
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
			if (rew->within == OUTSIDE) {
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

void sgTimePrint()
{
	struct Time *t;
	struct TimeElement *te;

	for (t = Time; t != NULL; t = t->next) {
		printf("Time %s is ", t->name);
		t->active ? printf("active\n") : printf("inactive\n");
		for (te = t->element; te != NULL; te = te->next) {
			printf("\tte->wday     = %x\n", te->wday);
			printf("\tte->from     = %d\n", te->from);
			printf("\tte->to       = %d\n", te->to);
			printf("\tte->y,m,d    = %d-%d-%d\n", te->y, te->m, te->d);
			printf("\tte->fromdate = %s\n", te->fromdate == 0 ?
			       "0" : niso(te->fromdate));
			printf("\tte->todate   = %s\n\n", te->todate == 0 ?
			       "0" : niso(te->todate));
		}
	}
}


/*
 * Ip functions
 */


void sgSetIpType(int type, char *file, int line)
{
	struct Ip *ip = sgIpLast(lastSource), *nip;
	char *p;
	char *f = file == NULL ? configFile : file;
	int l = line == 0 ? lineno : line;
	unsigned long octet, *op = NULL;
	if (type == SG_IPTYPE_HOST)
		ip->mask = 0xffffffff;
	if (type == SG_IPTYPE_RANGE) {
		if ((op = sgConvDot(ip->str)) == NULL)
			sgLogFatal("%s: FATAL: address error in %s line %d", progname, f, l);
		else
			ip->mask = *op;
		if (ip->net > ip->mask)
			sgLogFatal("%s: FATAL: iprange error in %s line %d", progname, f, l);
	}
	if (type == SG_IPTYPE_CLASS) {
		p = ip->str;
		if (*p == '/')
			p++;
		if ((op = sgConvDot(p)) == NULL)
			sgLogFatal("%s: FATAL: address error in %s line %d", progname, f, l);
		else
			ip->mask = *op;
	}
	if (type == SG_IPTYPE_CIDR) {
		p = ip->str;
		if (*p == '/')
			p++;
		octet = atoi(p);
		if (octet < 0 || octet > 32)
			sgLogFatal("%s: FATAL: prefix error /%s in %s line %d", progname, p, f, l);
		if (octet == 32)
			ip->mask = 0xffffffff;
		else
			ip->mask = 0xffffffff ^ (0xffffffff >> octet);
		ip->net = ip->net & ip->mask;
	}
	ip->type = type;
	nip = sgMalloc(sizeof(struct Ip));
	ip->next = nip;
}

void sgIp(char *name)
{
	struct Ip *ip;
	unsigned long *op;
	if (lastSource->ip == NULL) {
		ip = sgMalloc(sizeof(struct Ip));
		ip->next = NULL;
		lastSource->ip = ip;
		lastSource->lastip = ip;
	} else {
		ip = sgIpLast(lastSource);
	}
	if (ip->net_is_set == 0) {
		ip->net_is_set = 1;
		if ((op = sgConvDot(name)) == NULL)
			sgLogFatal("%s: FATAL: address error in %s line %d", progname, configFile, lineno);
		else
			ip->net = *op;
	} else {
		ip->str = sgMalloc(strlen(name) + 1);
		strcpy(ip->str, name);
	}
}

struct Ip *sgIpLast(struct Source *s)
{
	struct Ip *ip, *ret = NULL;
	for (ip = s->ip; ip != NULL; ip = ip->next)
		ret = ip;
	return ret;
}

/*
 * ACL functions
 */


void sgAcl(char *name, char *value, int within)
{
	struct Acl *acl;
	struct Source *source = NULL;
	struct Time *time = NULL;
	int def = 0;
	char *s;
	if (name != NULL) {
		/* due to some strange things in my yacc code */
		if ((s = (char *)strchr(name, ' ')) != NULL)
			*s = '\0';
		if ((s = (char *)strchr(name, '\t')) != NULL)
			*s = '\0';
		/*
		 * if(Acl != NULL){
		 * if((struct Acl *) sgAclFindName(name) != NULL){
		 *  sgLogFatal("%s: FATAL: ACL %s is defined in configfile %s",progname,name,configFile);
		 * }
		 * }
		 */
	}
	if (lastAcl != NULL && name == NULL && within == ELSE)
		name = lastAcl->name;
	acl = sgMalloc(sizeof(struct Acl));
	if (!strcmp(name, "default")) {
		defaultAcl = acl;
		def++;
	} else {
		if ((source = sgSourceFindName(name)) == NULL && !def)
			sgLogFatal("%s: FATAL: ACL source %s is not defined in configfile %s",
				   progname, name, configFile);
	}
	acl->name = sgMalloc(strlen(name) + 1);
	strcpy(acl->name, name);
	acl->active = within == ELSE ? 0 : 1;
	acl->source = source;
	acl->pass = NULL;
	acl->rewriteDefault = 1;
	acl->rewrite = NULL;
	acl->redirect = NULL;
	acl->within = within;
	acl->logfile = NULL;
	acl->next = NULL;
	if (value != NULL) {
		if ((time = sgTimeFindName(value)) == NULL)
			sgLogFatal("%s: FATAL: ACL time %s is not defined in configfile %s",
				   progname, value, configFile);
		acl->time = time;
	}
	if (Acl == NULL) {
		Acl = acl;
		lastAcl = acl;
	} else {
		lastAcl->next = acl;
		lastAcl = acl;
	}
}

void sgAclSetValue(char *what, char *value, int allowed)
{
	char *subval = NULL;
	struct Destination *dest = NULL;
	struct sgRewrite *rewrite = NULL;
	struct AclDest *acldest;
	int type = ACL_TYPE_TERMINATOR;
	if (!strcmp(what, "pass") || !strcmp(what, "next")) {
		if (!strcmp(value, "any") || !strcmp(value, "all")) {
			allowed = 1;
		} else if (!strcmp(value, "none")) {
			allowed = 0;
		} else if (!strcmp(value, "in-addr")) {
			type = ACL_TYPE_INADDR;
		} else if (!strncmp(value, "dnsbl", 5)) {
			subval = strstr(value, ":");
			type = ACL_TYPE_DNSBL;
		} else {
			if ((dest = sgDestFindName(value)) == NULL)
				sgLogFatal("%s: FATAL: ACL destination %s is not defined in configfile %s",
					   progname, value, configFile);
			type = ACL_TYPE_DEFAULT;
		}

		acldest = sgMalloc(sizeof(struct AclDest));
		acldest->name = sgMalloc(strlen(value) + 1);
		strcpy(acldest->name, value);
		acldest->dest = dest;
		acldest->access = allowed;
		acldest->next_source = !strcmp(what, "next");
		acldest->type = type;
		if (type == ACL_TYPE_DNSBL) {
			if ((subval == NULL) || (subval[1]) == '\0') { //Config does not define which dns domain to use
				acldest->dns_suffix = sgMalloc(strlen(".black.uribl.com") + 1);
				strcpy(acldest->dns_suffix, ".black.uribl.com");
			} else {
				subval = subval + 1;
				if (strspn(subval, ".-abcdefghijklmnopqrstuvwxyz0123456789") != strlen(subval))
					sgLogFatal("%s: FATAL: provided dnsbl \"%s\" doesn't look like a valid domain suffix", progname, subval);
				acldest->dns_suffix = sgMalloc(strlen(subval) + 1);
				strcpy(acldest->dns_suffix, ".");
				strcat(acldest->dns_suffix, subval);
			}
		}

		acldest->next = NULL;
		if (lastAcl->pass == NULL)
			lastAcl->pass = acldest;
		else
			lastAclDest->next = acldest;
		lastAclDest = acldest;
	}

	if (!strcmp(what, "rewrite")) {
		if (!strcmp(value, "none")) {
			lastAcl->rewriteDefault = 0;
			lastAcl->rewrite = NULL;
		} else {
			if ((rewrite = sgRewriteFindName(value)) == NULL)
				sgLogFatal("%s: FATAL: Rewrite %s is not defined in configfile %s",
					   progname, value, configFile);
			lastAcl->rewriteDefault = 0;
			lastAcl->rewrite = rewrite;
		}
	}
	if (!strcmp(what, "redirect")) {
		if (strcmp(value, "default")) {
			lastAcl->redirect = sgMalloc(strlen(value) + 1);
			strcpy(lastAcl->redirect, value);
		} else {
			lastAcl->redirect = NULL;
		}
	}
	if (!strcmp(what, "allow"))
		lastAcl->allow = 1;
}

struct Acl *sgAclFindName(char *name)
{
	struct Acl *p;
	for (p = Acl; p != NULL; p = p->next)
		if (!strcmp(name, p->name))
			return p;
	return NULL;
}


struct Acl *sgAclCheckSource(struct Source *source)
{
	struct Acl *acl = defaultAcl;
	int found = 0;
	if (source != NULL) {
		for (acl = Acl; acl != NULL; acl = acl->next) {
			if (acl->source == source) {
				if (acl->active) {
					found++;
					break;
				} else {
					if (acl->next->source == source && acl->next->active != 0) {
						found++;
						acl = acl->next;
						break;
					}
				}
			}
		}
	} else {
		sgLogDebug("source not found");
	}
	if (!found) {
		acl = defaultAcl;
		sgLogDebug("no ACL matching source, using default");
	}
	return acl;
}

char *strip_fqdn(char *domain)
{
	char *result;

	result = strstr(domain, ".");
	if (result == NULL)
		return NULL;
	return result + 1;
}

int is_blacklisted(char *domain, char *suffix)
{
	char target[MAX_BUF];
	struct addrinfo *res;
	int result;

	//Copying domain to target
	if (strlen(domain) + strlen(suffix) + 1 > MAX_BUF) {
		//Buffer overflow risk - just return and accept
		sgLogDebug("dnsbl : too long domain name - accepting without actual check");
		return 0;
	}
	strncpy(target, domain, strlen(domain) + 1);
	strcat(target, suffix);

	result = getaddrinfo(target, NULL, NULL, &res);
	if (result == 0) { //Result is defined
		freeaddrinfo(res);
		return 1;
	}
	//If anything fails (DNS server not reachable, any problem in the resolution,
	//let's not block anything.
	return 0;
}

int blocked_by_dnsbl(char *domain, char *suffix)
{
	char *dn = domain;

	while ((dn != NULL) && (strchr(dn, '.') != NULL)) { //No need to lookup "com.black.uribl.com"
		if (is_blacklisted(dn, suffix))
			return 1;
		dn = strip_fqdn(dn);
	}
	return 0;
}


char *sgAclAccess(struct Source *src, struct Acl *acl, struct SquidInfo *req)
{
	int access = 1, result;
	char *redirect = NULL, *dbdata = NULL, *p;
	struct sgRewrite *rewrite = NULL;
	struct AclDest *aclpass = NULL;
	if (acl == NULL)
		return NULL;
	if (acl->pass == NULL)
		acl->pass = defaultAcl->pass;
	if (acl->pass != NULL) {
		for (aclpass = acl->pass; aclpass != NULL; aclpass = aclpass->next) {
			if (aclpass->dest != NULL && !aclpass->dest->active)
				continue;
			if (aclpass->type == ACL_TYPE_TERMINATOR) {
				access = aclpass->access;
				break;
			}
			if (aclpass->type == ACL_TYPE_INADDR) {
				if (req->dot) {
					access = aclpass->access;
					break;
				}
				continue;
			}
			// http://www.yahoo.fr/ 172.16.2.32 - GET
			if (aclpass->type == ACL_TYPE_DNSBL) {
				if (req->dot)
					continue;
				if (blocked_by_dnsbl(req->domain, aclpass->dns_suffix)) {
					access = 0;
					break;
				}
				continue;
			}
			if (aclpass->dest->domainlistDb != NULL) {
				result = defined(aclpass->dest->domainlistDb, req->domain, &dbdata);
				if (result != DB_NOTFOUND) {
					if (result) {
						if (aclpass->access) {
							access++;
							break;
						} else {
							access = 0;
							break;
						}
					}
				} else {
				}
			}
			if (aclpass->dest->urllistDb != NULL && access) {
				result = defined(aclpass->dest->urllistDb, req->strippedurl, &dbdata);
				if (!result)
					result = defined(aclpass->dest->urllistDb, req->furl, &dbdata);
				if ((result) && (result != DB_NOTFOUND)) {
					if (aclpass->access) {
						access++;
						break;
					} else {
						access = 0;
						break;
					}
				} else {
				}
			}
			if (aclpass->dest->regExp != NULL && access) {
				if ((result = sgRegExpMatch(aclpass->dest->regExp, req->furl)) != 0) {
					if (aclpass->access) {
						access++;
						break;
					} else {
						access = 0;
						break;
					}
				}
			}
		}
		if (!access) {
			if (dbdata != NULL)
				redirect = dbdata;
			else if (acl->allow)
				access = 1;
			else if (aclpass->dest != NULL && aclpass->dest->redirect != NULL)
				redirect = aclpass->dest->redirect;
			else if (aclpass->dest != NULL && aclpass->dest->rewrite != NULL &&
				 (redirect =
					  sgRewriteExpression(aclpass->dest->rewrite, req->orig)) != NULL)
				;
			else if (acl->redirect == NULL)
				redirect = defaultAcl->redirect;
			else
				redirect = acl->redirect;
		} else if (aclpass->next_source) {
			redirect = NEXT_SOURCE;
		}
	} else { /* acl->pass == NULL, probably defaultAcl->pass == NULL */
		access = 0;
		redirect = defaultAcl->redirect;
	}
	if (acl->rewrite == NULL)
		rewrite = defaultAcl->rewrite;
	else
		rewrite = acl->rewrite;
	if (rewrite != NULL && access) {
		if ((p = sgRewriteExpression(rewrite, req->orig)) != NULL) {
			redirect = p;
			if (rewrite->logfile != NULL) {
				globalLogFile = rewrite->logfile;
				sgLogRequest(globalLogFile, req, acl, aclpass, rewrite, REQUEST_TYPE_REWRITE);
				return redirect;
			}
		}
	} else if (redirect != NULL && redirect != NEXT_SOURCE) {
		redirect = sgParseRedirect(redirect, req, acl, aclpass);
	}
	if (src != NULL && src->logfile != NULL)
		globalLogFile = src->logfile;
	if (aclpass == NULL || aclpass->dest == NULL) {
		if (defaultAcl->logfile != NULL)
			globalLogFile = defaultAcl->logfile;
	} else
	if (aclpass->dest->logfile != NULL) {
		globalLogFile = aclpass->dest->logfile;
	}
	if (globalLogFile != NULL) {
		if (redirect != NULL)
			sgLogRequest(globalLogFile, req, acl, aclpass, NULL, REQUEST_TYPE_REDIRECT);
		else
			sgLogRequest(globalLogFile, req, acl, aclpass, NULL, REQUEST_TYPE_PASS);
	}
	return redirect;
}

void yyerror(char *s)
{
	sgLogFatal("FATAL: %s in configfile %s line %d", s, configFile, lineno);
}


int yywrap()
{
	return 1;
}

/* returns 1 if user was found for the specified Source
 * returns a pointer to a UserInfo structure when found
 * handles all LDAP sub-lookups and caching
 */
int sgFindUser(struct Source *src, char *ident, struct UserInfo **rval)
{
	int i, found;
	int CacheTimeOut;
	char *interval;
	struct UserInfo *userinfo;
	static struct UserInfo info;

	 sgLogDebug("DEBUG: sgFindUser called with: %s", ident);

	/* defined in the userDB? */
	if (src->userDb != NULL && defined(src->userDb, ident, (char **)&userinfo) == 1) {
#ifdef HAVE_LIBLDAP
		/* LDAP user? */
		if (!userinfo->ldapuser) {
			*rval = userinfo;
			return 1; /* no, return regular user */
		}

		/* from here on, we assume it is an LDAP user */

		/* is this info valid? */
		interval = sgSettingGetValue("ldapcachetime");
		CacheTimeOut = atoi(interval != NULL ? interval : "0");
		if ((time(NULL) - userinfo->cachetime) <= CacheTimeOut) {
			if (userinfo->found)
				*rval = userinfo;
			return userinfo->found; /* yes */
		}
#endif
	} else {
		userinfo = NULL;       /* no record defined, must add our own*/
	}

	found = 0;                     /* assume not found */

#ifdef HAVE_LIBLDAP
	/* loop through all LDAP URLs and do a search */
	for (i = 0; i < src->ldapuserurlcount; i++) {
		found = sgDoLdapSearch(src->ldapuserurls[i], ident);

		/* cache every search in the user database */
		/* this should be safe, since squid only sends real idents
		 * that have been authenticated (?) */

		/* any record defined from above? */
		if (userinfo == NULL) {
			/* no, must use our own memory */
			userinfo = &info;
			info.status = 0;
			info.time = 0;
			info.consumed = 0;
			info.last = 0;
			info.ldapuser = 1;
			info.found = found;
			info.cachetime = time(NULL);
		} else {
			/* yes, just update the found flag */
			userinfo->found = found;
			userinfo->cachetime = time(NULL);
		}

		sgDbUpdate(src->userDb, ident, (char *)userinfo,
			   sizeof(struct UserInfo));
		sgLogDebug("Added LDAP source: %s", ident);

		if (found) {
			*rval = userinfo;
			break;
		}
	}
#endif
	return found;
}

#ifdef HAVE_LIBLDAP
/* returns 1 if ip was found for the specified Source
 * returns a pointer to a IpInfo structure when found
 * handles all LDAP sub-lookups and caching
 */
int sgFindIp(struct Source *src, char *net, struct IpInfo **rval)
{
	int i, found;
	int CacheTimeOut;
	char *interval;
	struct IpInfo *ipinfo;
	static struct IpInfo info;
/* DEBUG
 * sgLogError("debug : sgfindip called with: %s", net);
 */
	/* defined in the ipDB? */
	if (defined(src->ipDb, net, (char **)&ipinfo) == 1) {
		/* LDAP ip? */
		if (!ipinfo->ldapip) {
			*rval = ipinfo;
			return 1;      /* no, return regular ip */
		}

		/* from here on, we assume it is an LDAP ip */

		/* is this info valid? */
		interval = sgSettingGetValue("ldapcachetime");
		CacheTimeOut = atoi(interval != NULL ? interval : "0");
		if ((time(NULL) - ipinfo->cachetime) <= CacheTimeOut) {
			if (ipinfo->found)
				*rval = ipinfo;
			return ipinfo->found; /* yes */
		}
	} else {
		ipinfo = NULL;       /* no record defined, must add our own*/
	}

	found = 0;                     /* assume not found */

	/* loop through all LDAP URLs and do a search */
	for (i = 0; i < src->ldapipurlcount; i++) {
		found = sgDoLdapSearch(src->ldapipurls[i], net);

		/* cache every search in the ip database */
		/* this should be safe, since squid only sends real ip adresses (?) */
		/* any record defined from above? */
		if (ipinfo == NULL) {
			/* no, must use our own memory */
			ipinfo = &info;
			info.status = 0;
			info.time = 0;
			info.consumed = 0;
			info.last = 0;
			info.ldapip = 1;
			info.found = found;
			info.cachetime = time(NULL);
		} else {
			/* yes, just update the found flag */
			ipinfo->found = found;
			ipinfo->cachetime = time(NULL);
		}

		sgDbUpdate(src->ipDb, net, (char *)ipinfo,
			   sizeof(struct IpInfo));
		// DEBUG
		sgLogDebug("Added LDAP source: %s", net);

		if (found) {
			*rval = ipinfo;
			break;
		}
	}
	return found;
}

static int get_ldap_errno(LDAP *ld)
{
	int err = 0;
	if (ld)
		if (ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err) != LDAP_OPT_SUCCESS)
			err = 0;
	return err;
}

/*
 * expand_url - expand the %s codes in the given LDAP url
 *
 * Returns:  1 on success, 0 on error
 *
 *   char *expand;             destination buffer for expanded URL
 *   size_t expand_size;       size of dest buffer (sizeof() works here)
 *   char *url;                        original URL (MAXWORDLEN)
 *   char *s_item;             word to replace each occurance of %s with
 */
int expand_url(char *expand, size_t expand_size, const char *url,
	       const char *s_item)
{
	int item_length;
	char *end = expand + expand_size;

	item_length = strlen(s_item);

	while (*url && expand < end) {
		if (url[0] == '%' && url[1] == 's') {
			/* check buffer overrun */
			if ((expand + item_length) >= end)
				return 0;
			strcpy(expand, s_item);
			expand += item_length;

			url += 2;
		} else {
			*expand++ = *url++;
		}
	}

	if (expand < end) {
		*expand = '\0';        /* null terminate string */
		return 1;
	} else {
		return 0;
	}
}


/* does a raw LDAP search and returns 1 if found, 0 if not */
int sgDoLdapSearch(const char *url, const char *username)
{
	LDAPURLDesc *lud;
	LDAP *ld;
	int lderr = 0;
	LDAPMessage *ldapresult, *ldapentry;
	char *binddn = NULL, *bindpass = NULL;
	int ext_i;
	char **ldapvals;
	char buffer[MAX_BUF];
	int found = 0;
	int protoversion = -1;                 /* default to library defaults*/
	char *protosetting;

	/* Which protocol version should we use? */
	protosetting = sgSettingGetValue("ldapprotover");
	if (protosetting != NULL) {
		if (atoi(protosetting) == 3)
			protoversion = LDAP_VERSION3;
		else if (atoi(protosetting) == 2)
			protoversion = LDAP_VERSION2;
	}

	/* insert the username into the url, if needed... allow multiple %s */
	if (!expand_url(buffer, sizeof(buffer), url, username)) {
		sgLogError("%s: unable to expand LDAP URL: size: %u, username: "
			   "%s url: %s", progname, sizeof(buffer), username, url);
		return found;
	}

	/* Parse RFC2255 LDAP URL */
	if (ldap_url_parse(buffer, &lud)) {
		sgLogError("%s: can't parse LDAP url %s", progname, buffer);
		return found;
	}

	/* get a handle to an LDAP connection */
	if (ldap_is_ldapi_url(url)) {
		char *c = NULL;
		strncpy(buffer, url, sizeof(buffer));
		if ((c = strchr(buffer + strlen("ldapi://"), '/')) != NULL)
			*c = 0;
	} else {
		snprintf(buffer, sizeof(buffer), "%s://%s:%d", lud->lud_scheme, lud->lud_host, lud->lud_port);
	}

	if ((lderr = ldap_initialize(&ld, buffer)) != LDAP_SUCCESS) {
		sgLogError("%s: ldap_initialize(%s) failed: %s", progname,
			   buffer, ldap_err2string(lderr));
		ldap_free_urldesc(lud);
		return found;
	}

	/* force an LDAP protocol version if set */
	if (protoversion != -1) {
		if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
				    &protoversion) != LDAP_OPT_SUCCESS) {
			/* this will enter emergency mode */
			sgLogFatal("%s: FATAL: ldap_set_option failed: %s",
				   progname, ldap_err2string(get_ldap_errno(ld)));
		}
	}

	/*
	 * Set binddn and bindpass with values from the config
	 * file. Do this before the URL extentions so that they
	 * override on a per-block basis.
	 */
	binddn = sgSettingGetValue("ldapbinddn");
	bindpass = sgSettingGetValue("ldapbindpass");

	/* check for supported URL extensions:
	 *    bindname=<binddn>      (RFC2255)
	 *    x-bindpass=<bindpass>  (user-specific, allowed by RFC2255)
	 */
	for (ext_i = 0;
	     lud->lud_exts != NULL && lud->lud_exts[ext_i] != NULL;
	     ext_i++) {
		char *key = lud->lud_exts[ext_i];
		char *data;

		/* skip over any 'critical' markers */
		if (*key == '!')
			key++;

		/* find '=' sign (first one is all we care about) */
		data = strchr(key, '=');
		if (data == NULL)
			continue;       /* invalid extension, skip */
		data++;                 /* good extension, get data */

		/* do we recognize the key? */
		if (strncmp(key, "bindname=", 9) == 0) {
			binddn = data;
			sgLogDebug("Extracted binddn: %s", binddn);
		} else if (strncmp(key, "x-bindpass=", 11) == 0) {
			bindpass = data;
			sgLogDebug("Extracted x-bindpass: %s", bindpass);
		}
	}

	/* authenticate to the directory */
	if (ldap_simple_bind_s(ld, binddn, bindpass) != LDAP_SUCCESS) {
		sgLogError("%s: ldap_simple_bind_s failed: %s", progname,
			   ldap_err2string(get_ldap_errno(ld)));
		ldap_unbind(ld);
		ldap_free_urldesc(lud);
		return found;
	}

	/* Perform search */
	if (ldap_search_ext_s(ld, lud->lud_dn, lud->lud_scope, lud->lud_filter,
			      lud->lud_attrs, 0, NULL, NULL, NULL, -1,
			      &ldapresult) != LDAP_SUCCESS) {
		sgLogError("%s: ldap_search_ext_s failed: %s "

			   "(params: %s, %d, %s, %s)", progname, ldap_err2string(get_ldap_errno(ld)), lud->lud_dn, lud->lud_scope, lud->lud_filter, lud->lud_attrs[0]);

		ldap_unbind(ld);
		ldap_free_urldesc(lud);
		return found;
	}

	/* return hash */
	ldapentry = ldap_first_entry(ld, ldapresult);
	if (ldapentry != NULL) {
		/* Use first attribute to get value */
		ldapvals = ldap_get_values(ld, ldapentry, lud->lud_attrs[0]);
		if (ldapvals != NULL) {
			if (*ldapvals != NULL)
				found = 1;
			ldap_value_free(ldapvals);
		}
	}

	/* cleanup */
	ldap_msgfree(ldapresult);
	ldap_unbind(ld);
	ldap_free_urldesc(lud);
	return found;
}

#endif
