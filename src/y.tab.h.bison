/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     WORD = 258,
     END = 259,
     START_BRACKET = 260,
     STOP_BRACKET = 261,
     WEEKDAY = 262,
     DESTINATION = 263,
     REWRITE = 264,
     ACL = 265,
     TIME = 266,
     TVAL = 267,
     DVAL = 268,
     DVALCRON = 269,
     SOURCE = 270,
     CIDR = 271,
     IPCLASS = 272,
     CONTINUE = 273,
     IPADDR = 274,
     DBHOME = 275,
     DOMAINLIST = 276,
     URLLIST = 277,
     EXPRESSIONLIST = 278,
     IPLIST = 279,
     DOMAIN = 280,
     USER = 281,
     USERLIST = 282,
     USERQUERY = 283,
     LDAPUSERSEARCH = 284,
     USERQUOTA = 285,
     LDAPIPSEARCH = 286,
     IPQUOTA = 287,
     IP = 288,
     NL = 289,
     NUMBER = 290,
     PASS = 291,
     REDIRECT = 292,
     LOGDIR = 293,
     SUBST = 294,
     CHAR = 295,
     MINUTELY = 296,
     HOURLY = 297,
     DAILY = 298,
     WEEKLY = 299,
     DATE = 300,
     WITHIN = 301,
     OUTSIDE = 302,
     ELSE = 303,
     LOGFILE = 304,
     SYSLOG = 305,
     ANONYMOUS = 306,
     VERBOSE = 307,
     CONTINIOUS = 308,
     SPORADIC = 309,
     LDAPCACHETIME = 310,
     EXECUSERLIST = 311,
     EXECCMD = 312,
     LDAPPROTOVER = 313,
     LDAPBINDDN = 314,
     LDAPBINDPASS = 315,
     MYSQLUSERNAME = 316,
     MYSQLPASSWORD = 317,
     DATABASE = 318,
     QUOTED_STRING = 319
   };
#endif
/* Tokens.  */
#define WORD 258
#define END 259
#define START_BRACKET 260
#define STOP_BRACKET 261
#define WEEKDAY 262
#define DESTINATION 263
#define REWRITE 264
#define ACL 265
#define TIME 266
#define TVAL 267
#define DVAL 268
#define DVALCRON 269
#define SOURCE 270
#define CIDR 271
#define IPCLASS 272
#define CONTINUE 273
#define IPADDR 274
#define DBHOME 275
#define DOMAINLIST 276
#define URLLIST 277
#define EXPRESSIONLIST 278
#define IPLIST 279
#define DOMAIN 280
#define USER 281
#define USERLIST 282
#define USERQUERY 283
#define LDAPUSERSEARCH 284
#define USERQUOTA 285
#define LDAPIPSEARCH 286
#define IPQUOTA 287
#define IP 288
#define NL 289
#define NUMBER 290
#define PASS 291
#define REDIRECT 292
#define LOGDIR 293
#define SUBST 294
#define CHAR 295
#define MINUTELY 296
#define HOURLY 297
#define DAILY 298
#define WEEKLY 299
#define DATE 300
#define WITHIN 301
#define OUTSIDE 302
#define ELSE 303
#define LOGFILE 304
#define SYSLOG 305
#define ANONYMOUS 306
#define VERBOSE 307
#define CONTINIOUS 308
#define SPORADIC 309
#define LDAPCACHETIME 310
#define EXECUSERLIST 311
#define EXECCMD 312
#define LDAPPROTOVER 313
#define LDAPBINDDN 314
#define LDAPBINDPASS 315
#define MYSQLUSERNAME 316
#define MYSQLPASSWORD 317
#define DATABASE 318
#define QUOTED_STRING 319




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 83 "sg.y"
{
  char *string;
  char *tval;
  char *dval;
  char *dvalcron;
  int  *integer;
}
/* Line 1489 of yacc.c.  */
#line 185 "y.tab.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

