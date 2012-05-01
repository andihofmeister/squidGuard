/*
  By accepting this notice, you agree to be bound by the following
  agreements:
  
  This software product, squidGuard, is copyrighted (C) 1998-2009
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

%{

#include "y.tab.h"
#include "sg.h"

%}

ignore   [,\t\r ]+
s        [\t ]
d        [0-9]
ip       {d}{1,3}\.{d}{1,3}\.{d}{1,3}\.{d}{1,3}
tval     {d}{d}[:]{d}{d}
dval     {d}{d}{d}{d}[\.-]{d}{d}[\.-]{d}{d}
dvalcron ({d}{d}{d}{d}|[\*])[\.-]({d}{d}|[\*])[\.-]({d}{d}|[\*])
weekday  (mon|mondays?|tue|tuesdays?|wed|wednesdays?|thu|thursdays?|fri|fridays?|sat|saturdays?|sun|sundays?)
weekdays (({weekday}{s}*[, \t]+{s}*)*{weekday})|[\*]

/* from RFC1779:

<name> ::= <name-component> ( <spaced-separator> )
          | <name-component> <spaced-separator> <name>

   <spaced-separator> ::= <optional-space>
                   <separator>
                   <optional-space>

   <separator> ::=  "," | ";"

   <optional-space> ::= ( <CR> ) *( " " )

   <name-component> ::= <attribute>
           | <attribute> <optional-space> "+"
             <optional-space> <name-component>

   <attribute> ::= <string>
           | <key> <optional-space> "=" <optional-space> <string>

   <key> ::= 1*( <keychar> ) | "OID." <oid> | "oid." <oid>
   <keychar> ::= letters, numbers, and space

   <oid> ::= <digitstring> | <digitstring> "." <oid>
   <digitstring> ::= 1*<digit>
   <digit> ::= digits 0-9

   <string> ::= *( <stringchar> | <pair> )
            | '"' *( <stringchar> | <special> | <pair> ) '"'
            | "#" <hex>

   <special> ::= "," | "=" | <CR> | "+" | "<" |  ">"
            | "#" | ";"

   <pair> ::= "\" ( <special> | "\" | '"')
   <stringchar> ::= any character except <special> or "\" or '"'

   <hex> ::= 2*<hexchar>
   <hexchar> ::= 0-9, a-f, A-F
*/


%x REDIRECT_STATE
%x EXEC_STATE
%x STRING_STATE

%%

       char string_buf[MAX_BUF];
       char *string_buf_ptr;

[ \t]*#.*        ;
"{"         return START_BRACKET;
"}"         return STOP_BRACKET; 
^dest        return DESTINATION;
^destination return DESTINATION;
^src         return SOURCE;
^source      return SOURCE;
^rew         return REWRITE;
^rewrite     return REWRITE;
^time        return TIME;
^syslog      return SYSLOG;
^acl         return ACL;
^dbhome                return DBHOME;
^logdir                return LOGDIR;
^ldapcachetime return LDAPCACHETIME;
^ldapprotover  return LDAPPROTOVER;
^ldapbinddn    return LDAPBINDDN;
^ldapbindpass  return LDAPBINDPASS;
^mysqlusername return MYSQLUSERNAME;
^mysqlpassword return MYSQLPASSWORD;
^mysqldb       return DATABASE;
domainlist  return DOMAINLIST;
urllist     return URLLIST;
expressionlist return EXPRESSIONLIST;
iplist      return IPLIST;
user        return USER;
userlist    return USERLIST;
userquery   {
	BEGIN REDIRECT_STATE;
	return USERQUERY;
	}
ldapusersearch {
       /* use the REDIRECT_STATE logic, since it handles URLs nicely */
       /* BEGIN REDIRECT_STATE; */
       return LDAPUSERSEARCH;
       }
ldapipsearch {
       /* use the REDIRECT_STATE logic, since it handles URLs nicely */
       BEGIN REDIRECT_STATE;
       return LDAPIPSEARCH;
       }
execuserlist {
       BEGIN EXEC_STATE;
       return EXECUSERLIST;
       }
userquota   return USERQUOTA;
domain      return DOMAIN;
pass        return PASS;
rewrite     return REWRITE;
redirect    { BEGIN REDIRECT_STATE; return REDIRECT; }
minutely    return MINUTELY;
hourly      return HOURLY;
daily       return DAILY;
weekly      return WEEKLY;
continuous  return CONTINIOUS;
continue    return CONTINUE;
sporadic    return SPORADIC;
date        return DATE;
anonymous   return ANONYMOUS;
verbose     return VERBOSE;
log         return LOGFILE;
logfile     return LOGFILE;
{weekdays} {yylval.string = yytext; return WEEKDAY;}
within return WITHIN;
outside return OUTSIDE;
else return ELSE;
ip          return IP;
{ip}        {yylval.string = yytext; return IPADDR;}
[/]{d}+     {yylval.string = yytext; return CIDR;}
[/]{ip}     {yylval.string = yytext; return IPCLASS;}
{tval}      {yylval.string = yytext; return TVAL;}
{dval}      {yylval.string = yytext; return DVAL;}
{dvalcron}  {yylval.string = yytext; return DVALCRON;}
{d}+        {yylval.string = yytext; return NUMBER;}

<REDIRECT_STATE>[a-zA-Z3\/][a-zA-Z0-9/_\-\.\,\(\)\/\:\%\+\?=&~!\|]*  { yylval.string = yytext ; BEGIN 0; return WORD;}
<REDIRECT_STATE>[ \t]+     ;
<REDIRECT_STATE>\n        {lineno++;}
<REDIRECT_STATE>.         {return yytext[0];}

<EXEC_STATE>[^\n]* { yylval.string = yytext; BEGIN 0; return EXECCMD; }
<EXEC_STATE>\n     {lineno++;}

\"                 { string_buf_ptr = string_buf; BEGIN STRING_STATE; }
<STRING_STATE>\"   { *string_buf_ptr = '\0'; yylval.string = string_buf; BEGIN 0; return QUOTED_STRING; }
<STRING_STATE>\\x[0-9a-fA-F]{2} {
                     if (string_buf_ptr-string_buf < sizeof(string_buf)-1)
                     {
                       int hexcode;
                       sscanf( yytext + 2, "%x", &hexcode );
                       *string_buf_ptr++ = (char) hexcode;
                     }
                   }
<STRING_STATE>\\n  { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = '\n'; }
<STRING_STATE>\\r  { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = '\r'; }
<STRING_STATE>\\a  { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = '\a'; }
<STRING_STATE>\\b  { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = '\b'; }
<STRING_STATE>\\t  { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = '\t'; }
<STRING_STATE>\n   { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = '\n'; }
<STRING_STATE>\\\n { /* continuation line - ignore the \ and newline */; }
<STRING_STATE>\\.  { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = yytext[1];  }
<STRING_STATE>[^\\\n\"]+ {
                     char *yyptr = yytext;
                     while (*yyptr)
                     {
                       if (string_buf_ptr-string_buf >= sizeof(string_buf)-1)
                         break;
                       *string_buf_ptr++ = *yyptr++;
                        }
                   }
<STRING_STATE>.    { if (string_buf_ptr-string_buf < sizeof(string_buf)-1) *string_buf_ptr++ = yytext[1];  }

[a-zA-Z\/][a-zA-Z0-9/_\-\.\/\:\%\+\@\,\?=&\à\é\è\ñ\á\ì\í\ò\ó\ù\ú\*]*  {yylval.string = yytext ; return WORD;}
s@(([^@}]|\\@|\\\})+)@(([^@}]|\\@|\\\})+)@[girR]* {yylval.string = yytext; return SUBST;}
[ \t]+     ;
\n        {lineno++;}
.         {return yytext[0];}


%%

