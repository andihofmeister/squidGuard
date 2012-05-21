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

%option nounput
%option noinput

%{

#include "y.tab.h"
#include "sgMemory.h"

#define STRBUF_SIZE 16384
char string_buf[STRBUF_SIZE];

char *string_buf_ptr = NULL;
int lineno = 0;

%}

ignore   [,\t\r ]+
s        [\t ]
d        [0-9]
tval     {d}{d}[:]{d}{d}
dval     {d}{d}{d}{d}[\.-]{d}{d}[\.-]{d}{d}
dvalcron ({d}{d}{d}{d}|[\*])[\.-]({d}{d}|[\*])[\.-]({d}{d}|[\*])
weekday  (mon|mondays?|tue|tuesdays?|wed|wednesdays?|thu|thursdays?|fri|fridays?|sat|saturdays?|sun|sundays?)
weekdays (({weekday}{s}*[, \t]+{s}*)*{weekday})|[\*]
ipv4     {d}{1,3}\.{d}{1,3}\.{d}{1,3}\.{d}{1,3}(\/{d}{1,2})?

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


"{"         { return START_BRACKET; }
"}"         { return STOP_BRACKET; }
any         { return ANY; }
none        { return NONE; }
dest        { return DESTINATION; }
destination { return DESTINATION; }
else        { return ELSE; }
src         { return SOURCE; }
source      { return SOURCE; }
rew         { return REWRITE; }
rewrite     { return REWRITE; }
set         { return SET; }
time        { return TIME; }
acl         { return ACL; }
domainlist  { return DOMAINLIST; }
urllist     { return URLLIST; }
expressionlist { return EXPRESSIONLIST; }
dnsbl       { return DNSBL; }
iplist      { return IPLIST; }
user        { return USER; }
group       { return GROUP; }
netgroup    { return NETGROUP; }
userlist    { return USERLIST; }

ldapusersearch {
       /* use the REDIRECT_STATE logic, since it handles URLs nicely */
       /* BEGIN REDIRECT_STATE; */
       return LDAPUSERSEARCH;
       }
ldapipsearch  {
       /* use the REDIRECT_STATE logic, since it handles URLs nicely */
       BEGIN REDIRECT_STATE;
       return LDAPIPSEARCH;
       }
execuserlist { BEGIN EXEC_STATE; return EXECUSERLIST; }
domain       { return DOMAIN; }
pass         { return PASS; }
next         { return NEXT; }
redirect     { BEGIN REDIRECT_STATE; return REDIRECT; }
allow        { return ALLOW; }
tag          { return TAG; }
continue     { return CONTINUE; }
date         { return DATE; }
anonymous    { return ANONYMOUS; }
verbose      { return VERBOSE; }
log          { return LOGFILE; }
logfile      { return LOGFILE; }
weekly       { return WEEKLY; }
{weekdays}   { yylval.string = sgStrdup(yytext); return WEEKDAY;}
within       { return WITHIN; }
outside      { return OUTSIDE; }
ip           { return IP; }
{ipv4}       { yylval.string = sgStrdup(yytext); return QUOTED_STRING; }
{tval}       { yylval.string = sgStrdup(yytext); return TVAL;}
{dval}       { yylval.string = sgStrdup(yytext); return DVAL;}
{dvalcron}   { yylval.string = sgStrdup(yytext); return DVALCRON;}
{d}+         { yylval.string = sgStrdup(yytext); return NUMBER;}

<REDIRECT_STATE>[a-zA-Z3\/][a-zA-Z0-9/_\-\.\,\(\)\/\:\%\+\?=&~!\|]*  { yylval.string = sgStrdup(yytext) ; BEGIN 0; return WORD;}
<REDIRECT_STATE>[ \t]+     ;
<REDIRECT_STATE>\n        {lineno++;}
<REDIRECT_STATE>.         {return yytext[0];}

<EXEC_STATE>[^\n]* { yylval.string = sgStrdup(yytext); BEGIN 0; return EXECCMD; }
<EXEC_STATE>\n     {lineno++;}

\"                 { string_buf_ptr = string_buf; BEGIN STRING_STATE; }
<STRING_STATE>\"   { *string_buf_ptr = '\0'; yylval.string = sgStrdup(string_buf); BEGIN 0; return QUOTED_STRING; }
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

s@(([^@}]|\\@|\\\})+)@(([^@}]|\\@|\\\})+)@[girR]* {yylval.string = sgStrdup(yytext); return SUBST;}

[a-zA-Z\/][a-zA-Z0-9/_\-\.\/\:\%\+\@\,\?=&\à\é\è\ñ\á\ì\í\ò\ó\ù\ú\*]*  {yylval.string = sgStrdup(yytext); return WORD;}

[ \t]*#.*  ;
[ \t]+     ;
\n        {lineno++;}
.         {return yytext[0];}


%%

