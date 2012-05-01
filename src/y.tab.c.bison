/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



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




/* Copy the first part of user declarations.  */
#line 20 "sg.y"

#include "sg.h"
extern int globalDebug;
#ifdef USE_SYSLOG
extern int globalSyslog;
#endif

#ifdef HAVE_LIBLDAP
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

void rfc1738_unescape(char *);
void
rfc1738_unescape(char *s)
{
    char hexnum[3];
    int i, j;                   /* i is write, j is read */
    unsigned int x;
    for (i = j = 0; s[j]; i++, j++) {
        s[i] = s[j];
        if (s[i] != '%')
            continue;
        if (s[j + 1] == '%') {  /* %% case */
            j++;
            continue;
        }
        if (s[j + 1] && s[j + 2]) {
            if (s[j + 1] == '0' && s[j + 2] == '0') {   /* %00 case */
                j += 2;
                continue;
            }
            hexnum[0] = s[j + 1];
            hexnum[1] = s[j + 2];
            hexnum[2] = '\0';
            if (1 == sscanf(hexnum, "%x", &x)) {
                s[i] = (char) (0x0ff & x);
                j += 2;
            }
        }
    }
    s[i] = '\0';
}



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

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
/* Line 187 of yacc.c.  */
#line 295 "y.tab.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 308 "y.tab.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   265

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  69
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  59
/* YYNRULES -- Number of rules.  */
#define YYNRULES  153
/* YYNRULES -- Number of states.  */
#define YYNSTATES  235

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   319

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    68,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    67,    65,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,    66,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     5,     7,     9,    11,    13,    16,    19,
      22,    25,    28,    31,    34,    37,    40,    43,    45,    47,
      50,    55,    56,    59,    62,    65,    68,    71,    74,    78,
      81,    84,    87,    90,    93,    97,   101,   106,   111,   114,
     117,   122,   123,   126,   129,   132,   135,   138,   143,   148,
     153,   158,   161,   164,   167,   170,   174,   178,   183,   188,
     191,   193,   194,   197,   200,   201,   204,   207,   212,   213,
     216,   218,   222,   226,   231,   232,   242,   243,   246,   249,
     252,   255,   259,   263,   268,   273,   276,   277,   280,   284,
     287,   289,   291,   292,   295,   299,   303,   308,   311,   313,
     316,   321,   322,   325,   327,   330,   333,   337,   341,   346,
     351,   354,   357,   362,   363,   366,   367,   368,   374,   375,
     376,   382,   383,   387,   388,   394,   398,   401,   403,   408,
     412,   415,   417,   419,   421,   423,   424,   427,   429,   431,
     433,   435,   437,   439,   441,   443,   445,   447,   449,   451,
     453,   455,   457,   459
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      70,     0,    -1,   126,    -1,     3,    -1,    64,    -1,     3,
      -1,    64,    -1,    20,    71,    -1,    50,    71,    -1,    38,
      71,    -1,    55,    35,    -1,    58,    35,    -1,    59,    72,
      -1,    60,    71,    -1,    61,    71,    -1,    62,    71,    -1,
      63,    71,    -1,     5,    -1,     6,    -1,     8,     3,    -1,
      85,    83,    87,    84,    -1,    -1,    87,    88,    -1,    21,
      71,    -1,    21,    65,    -1,    22,    71,    -1,    22,    65,
      -1,    23,    65,    -1,    23,    66,    71,    -1,    23,    71,
      -1,    37,    71,    -1,     9,    71,    -1,    46,     3,    -1,
      47,     3,    -1,    49,    51,    71,    -1,    49,    52,    71,
      -1,    49,    51,    52,    71,    -1,    49,    52,    51,    71,
      -1,    49,    71,    -1,    15,     3,    -1,    89,    83,    91,
      84,    -1,    -1,    91,    92,    -1,    25,    93,    -1,    26,
      94,    -1,    27,    71,    -1,    56,    57,    -1,    30,    35,
      35,    42,    -1,    30,    35,    35,    43,    -1,    30,    35,
      35,    44,    -1,    30,    35,    35,    35,    -1,    33,   105,
      -1,    24,    71,    -1,    46,     3,    -1,    47,     3,    -1,
      49,    51,    71,    -1,    49,    52,    71,    -1,    49,    51,
      52,    71,    -1,    49,    52,    51,    71,    -1,    49,    71,
      -1,    18,    -1,    -1,    93,    71,    -1,    93,    67,    -1,
      -1,    94,    71,    -1,    94,    67,    -1,    10,    83,    96,
      84,    -1,    -1,    96,    98,    -1,     3,    -1,     3,    46,
       3,    -1,     3,    47,     3,    -1,    97,    83,   100,    84,
      -1,    -1,    97,    83,   100,    84,    48,    99,    83,   100,
      84,    -1,    -1,   100,   101,    -1,    36,   102,    -1,     9,
       3,    -1,    37,    71,    -1,    49,    51,    71,    -1,    49,
      52,    71,    -1,    49,    51,    52,    71,    -1,    49,    52,
      51,    71,    -1,    49,    71,    -1,    -1,   102,     3,    -1,
     102,    68,     3,    -1,   102,    67,    -1,    16,    -1,    17,
      -1,    -1,   105,   106,    -1,   105,   106,   103,    -1,   105,
     106,   104,    -1,   105,   106,    65,   106,    -1,   105,    67,
      -1,    19,    -1,     9,     3,    -1,   107,    83,   109,    84,
      -1,    -1,   109,   110,    -1,    39,    -1,    46,     3,    -1,
      47,     3,    -1,    49,    51,    71,    -1,    49,    52,    71,
      -1,    49,    51,    52,    71,    -1,    49,    52,    51,    71,
      -1,    49,    71,    -1,    11,     3,    -1,   111,    83,   113,
      84,    -1,    -1,   113,   114,    -1,    -1,    -1,    44,   115,
       3,   116,   120,    -1,    -1,    -1,    44,   117,     7,   118,
     120,    -1,    -1,    45,   119,   122,    -1,    -1,   120,   121,
     124,    65,   124,    -1,   124,    65,   124,    -1,   123,   120,
      -1,   123,    -1,   123,    65,   123,   120,    -1,   123,    65,
     123,    -1,   125,   120,    -1,   125,    -1,    13,    -1,    12,
      -1,    14,    -1,    -1,   126,   127,    -1,    85,    -1,    90,
      -1,    86,    -1,    73,    -1,    75,    -1,    74,    -1,    77,
      -1,    78,    -1,    79,    -1,    76,    -1,    80,    -1,    81,
      -1,    82,    -1,    95,    -1,   108,    -1,   112,    -1,    34,
      -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   127,   127,   130,   130,   133,   133,   136,   139,   142,
     145,   148,   151,   154,   157,   160,   163,   167,   171,   174,
     177,   181,   182,   185,   186,   187,   188,   189,   190,   191,
     192,   193,   194,   195,   196,   197,   198,   199,   200,   203,
     206,   209,   210,   213,   214,   215,   219,   220,   221,   222,
     223,   224,   225,   226,   227,   228,   229,   230,   231,   232,
     233,   235,   236,   237,   240,   241,   242,   245,   248,   249,
     252,   253,   254,   257,   259,   258,   263,   264,   267,   268,
     269,   270,   271,   272,   273,   274,   277,   278,   279,   280,
     283,   286,   288,   289,   290,   291,   292,   293,   296,   299,
     302,   305,   306,   310,   311,   312,   313,   314,   315,   316,
     317,   321,   324,   327,   328,   332,   333,   332,   334,   335,
     334,   336,   336,   340,   340,   341,   344,   345,   346,   347,
     348,   349,   352,   355,   358,   361,   362,   366,   367,   368,
     369,   370,   371,   372,   373,   374,   375,   376,   377,   378,
     379,   380,   381,   382
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "WORD", "END", "START_BRACKET",
  "STOP_BRACKET", "WEEKDAY", "DESTINATION", "REWRITE", "ACL", "TIME",
  "TVAL", "DVAL", "DVALCRON", "SOURCE", "CIDR", "IPCLASS", "CONTINUE",
  "IPADDR", "DBHOME", "DOMAINLIST", "URLLIST", "EXPRESSIONLIST", "IPLIST",
  "DOMAIN", "USER", "USERLIST", "USERQUERY", "LDAPUSERSEARCH", "USERQUOTA",
  "LDAPIPSEARCH", "IPQUOTA", "IP", "NL", "NUMBER", "PASS", "REDIRECT",
  "LOGDIR", "SUBST", "CHAR", "MINUTELY", "HOURLY", "DAILY", "WEEKLY",
  "DATE", "WITHIN", "OUTSIDE", "ELSE", "LOGFILE", "SYSLOG", "ANONYMOUS",
  "VERBOSE", "CONTINIOUS", "SPORADIC", "LDAPCACHETIME", "EXECUSERLIST",
  "EXECCMD", "LDAPPROTOVER", "LDAPBINDDN", "LDAPBINDPASS", "MYSQLUSERNAME",
  "MYSQLPASSWORD", "DATABASE", "QUOTED_STRING", "'-'", "'i'", "','", "'!'",
  "$accept", "start", "STRING", "LDAPDNSTR", "dbhome", "sg_syslog",
  "logdir", "ldapcachetime", "ldapprotover", "ldapbinddn", "ldapbindpass",
  "mysqlusername", "mysqlpassword", "mysqldb", "start_block", "stop_block",
  "destination", "destination_block", "destination_contents",
  "destination_content", "source", "source_block", "source_contents",
  "source_content", "domain", "user", "acl_block", "acl_contents", "acl",
  "acl_content", "@1", "access_contents", "access_content", "access_pass",
  "cidr", "ipclass", "ips", "ip", "rew", "rew_block", "rew_contents",
  "rew_content", "time", "time_block", "time_contents", "time_content",
  "@2", "@3", "@4", "@5", "@6", "ttime", "@7", "date", "dval", "tval",
  "dvalcron", "statements", "statement", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,    45,   105,    44,    33
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    69,    70,    71,    71,    72,    72,    73,    74,    75,
      76,    77,    78,    79,    80,    81,    82,    83,    84,    85,
      86,    87,    87,    88,    88,    88,    88,    88,    88,    88,
      88,    88,    88,    88,    88,    88,    88,    88,    88,    89,
      90,    91,    91,    92,    92,    92,    92,    92,    92,    92,
      92,    92,    92,    92,    92,    92,    92,    92,    92,    92,
      92,    93,    93,    93,    94,    94,    94,    95,    96,    96,
      97,    97,    97,    98,    99,    98,   100,   100,   101,   101,
     101,   101,   101,   101,   101,   101,   102,   102,   102,   102,
     103,   104,   105,   105,   105,   105,   105,   105,   106,   107,
     108,   109,   109,   110,   110,   110,   110,   110,   110,   110,
     110,   111,   112,   113,   113,   115,   116,   114,   117,   118,
     114,   119,   114,   121,   120,   120,   122,   122,   122,   122,
     122,   122,   123,   124,   125,   126,   126,   127,   127,   127,
     127,   127,   127,   127,   127,   127,   127,   127,   127,   127,
     127,   127,   127,   127
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     1,     1,     1,     1,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     1,     1,     2,
       4,     0,     2,     2,     2,     2,     2,     2,     3,     2,
       2,     2,     2,     2,     3,     3,     4,     4,     2,     2,
       4,     0,     2,     2,     2,     2,     2,     4,     4,     4,
       4,     2,     2,     2,     2,     3,     3,     4,     4,     2,
       1,     0,     2,     2,     0,     2,     2,     4,     0,     2,
       1,     3,     3,     4,     0,     9,     0,     2,     2,     2,
       2,     3,     3,     4,     4,     2,     0,     2,     3,     2,
       1,     1,     0,     2,     3,     3,     4,     2,     1,     2,
       4,     0,     2,     1,     2,     2,     3,     3,     4,     4,
       2,     2,     4,     0,     2,     0,     0,     5,     0,     0,
       5,     0,     3,     0,     5,     3,     2,     1,     4,     3,
       2,     1,     1,     1,     1,     0,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
     135,     0,     2,     1,     0,     0,     0,     0,     0,     0,
     153,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     140,   142,   141,   146,   143,   144,   145,   147,   148,   149,
     137,   139,     0,   138,   150,     0,   151,     0,   152,   136,
      19,    99,    17,    68,   111,    39,     3,     4,     7,     9,
       8,    10,    11,     5,     6,    12,    13,    14,    15,    16,
      21,    41,   101,   113,     0,     0,     0,     0,     0,    70,
      18,    67,     0,    69,     0,     0,     0,     0,     0,     0,
       0,     0,    20,    22,    60,     0,    61,    64,     0,     0,
      92,     0,     0,     0,     0,    40,    42,   103,     0,     0,
       0,   100,   102,   115,   121,   112,   114,     0,     0,    76,
      31,    24,    23,    26,    25,    27,     0,    29,    30,    32,
      33,     0,     0,    38,    52,    43,    44,    45,     0,    51,
      53,    54,     0,     0,    59,    46,   104,   105,     0,     0,
     110,     0,     0,     0,    71,    72,     0,    28,     0,    34,
       0,    35,    63,    62,    66,    65,     0,    98,    97,    93,
       0,    55,     0,    56,     0,   106,     0,   107,   116,   119,
     132,   134,   122,   127,   131,     0,    86,     0,     0,    73,
      77,    36,    37,    50,    47,    48,    49,    90,    91,     0,
      94,    95,    57,    58,   108,   109,     0,     0,   133,     0,
     126,     0,   130,    79,    78,    80,     0,     0,    85,    74,
      96,   117,   120,   129,     0,     0,    87,    89,     0,     0,
      81,     0,    82,     0,   128,     0,   125,    88,    83,    84,
      76,     0,     0,   124,    75
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    48,    55,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    43,    71,    30,    31,    65,    83,
      32,    33,    66,    96,   125,   126,    34,    64,    72,    73,
     223,   146,   180,   204,   190,   191,   129,   159,    35,    36,
      67,   102,    37,    38,    68,   106,   141,   196,   142,   197,
     143,   200,   214,   172,   173,   201,   174,     2,    39
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -189
static const yytype_int16 yypact[] =
{
    -189,    21,   163,  -189,    10,    27,    35,    41,    42,    55,
    -189,    55,    55,    12,    14,    76,    55,    55,    55,    55,
    -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,
      35,  -189,    35,  -189,  -189,    35,  -189,    35,  -189,  -189,
    -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,
    -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,
    -189,  -189,  -189,  -189,    25,   182,   209,   201,    -3,   -13,
    -189,  -189,    35,  -189,    55,     7,    20,    26,    55,   109,
     121,    29,  -189,  -189,  -189,    55,  -189,  -189,    55,    90,
    -189,   129,   130,    36,   -33,  -189,  -189,  -189,   131,   132,
      43,  -189,  -189,   134,  -189,  -189,  -189,   135,   139,  -189,
    -189,  -189,  -189,  -189,  -189,  -189,    55,  -189,  -189,  -189,
    -189,    49,    52,  -189,  -189,     9,    19,  -189,   108,   -17,
    -189,  -189,    54,    53,  -189,  -189,  -189,  -189,    56,    72,
    -189,   141,   138,    22,  -189,  -189,   120,  -189,    55,  -189,
      55,  -189,  -189,  -189,  -189,  -189,    18,  -189,  -189,   114,
      55,  -189,    55,  -189,    55,  -189,    55,  -189,  -189,  -189,
    -189,  -189,  -189,    13,   140,   143,  -189,    55,    45,   106,
    -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,   128,
    -189,  -189,  -189,  -189,  -189,  -189,   140,   140,  -189,   145,
     147,    97,   147,  -189,     1,  -189,    96,    99,  -189,  -189,
    -189,   147,   147,   140,   140,   140,  -189,  -189,   158,    55,
    -189,    55,  -189,    35,   147,   100,  -189,  -189,  -189,  -189,
    -189,   140,   120,  -189,  -189
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -189,  -189,   -11,  -189,  -189,  -189,  -189,  -189,  -189,  -189,
    -189,  -189,  -189,  -189,   -21,   -48,  -189,  -189,  -189,  -189,
    -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,
    -189,   -66,  -189,  -189,  -189,  -189,  -189,   -19,  -189,  -189,
    -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,  -189,
    -189,  -159,  -189,  -189,   -31,  -188,  -189,  -189,  -189
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -124
static const yytype_int16 yytable[] =
{
      49,    50,   157,    70,   216,    56,    57,    58,    59,    60,
      46,    61,    46,    40,    62,   202,    63,    82,    95,   101,
     105,     3,    46,    46,   135,   198,   225,   226,    69,    46,
      41,    70,    46,   107,   108,   170,   171,   211,   212,    46,
      42,   103,   104,   233,    44,    45,    46,    51,    46,    52,
     158,   109,    46,   183,   224,    46,    46,    46,    46,    46,
     184,   185,   186,   110,   112,   114,   117,   118,   217,   218,
     123,    47,   111,    47,   124,    46,   152,   127,   199,    53,
     121,   122,   134,    47,    47,   113,   154,   132,   133,   140,
      47,   115,   116,    47,   138,   139,   206,   207,   179,    46,
      47,   148,    46,   150,   162,   147,   160,    47,   164,    47,
     149,   151,   119,    47,   153,   155,    47,    47,    47,    47,
      47,   161,   163,   166,   120,   128,    70,   165,   167,   175,
     187,   188,   130,   131,   136,   137,    47,   181,   144,   182,
      54,  -118,   145,   156,   168,   169,   203,   157,   219,   192,
     221,   193,   198,   194,   209,   195,   176,   177,   170,  -123,
      47,   227,   215,    47,   232,   231,   205,   208,   213,   178,
     210,     4,     5,     6,     7,     0,     0,     0,     8,   189,
       0,     0,     0,     9,   234,     0,     0,     0,    70,     0,
       0,    74,     0,     0,     0,   220,   222,    10,     0,     0,
       0,    11,   230,    75,    76,    77,     0,    70,   228,     0,
     229,     0,     0,    12,     0,    70,     0,     0,    13,    78,
       0,    14,    15,    16,    17,    18,    19,    84,    79,    80,
       0,    81,     0,    85,    86,    87,    88,     0,     0,    89,
      97,     0,    90,     0,     0,     0,     0,    98,    99,     0,
     100,     0,     0,     0,     0,    91,    92,     0,    93,     0,
       0,     0,     0,     0,     0,    94
};

static const yytype_int16 yycheck[] =
{
      11,    12,    19,     6,     3,    16,    17,    18,    19,    30,
       3,    32,     3,     3,    35,   174,    37,    65,    66,    67,
      68,     0,     3,     3,    57,    12,   214,   215,     3,     3,
       3,     6,     3,    46,    47,    13,    14,   196,   197,     3,
       5,    44,    45,   231,     3,     3,     3,    35,     3,    35,
      67,    72,     3,    35,   213,     3,     3,     3,     3,     3,
      42,    43,    44,    74,    75,    76,    77,    78,    67,    68,
      81,    64,    65,    64,    85,     3,    67,    88,    65,     3,
      51,    52,    93,    64,    64,    65,    67,    51,    52,   100,
      64,    65,    66,    64,    51,    52,    51,    52,   146,     3,
      64,    52,     3,    51,    51,   116,    52,    64,    52,    64,
     121,   122,     3,    64,   125,   126,    64,    64,    64,    64,
      64,   132,   133,    51,     3,    35,     6,   138,   139,     9,
      16,    17,     3,     3,     3,     3,    64,   148,     3,   150,
      64,     7,     3,    35,     3,     7,     3,    19,    52,   160,
      51,   162,    12,   164,    48,   166,    36,    37,    13,    12,
      64,     3,    65,    64,   230,    65,   177,   178,   199,    49,
     189,     8,     9,    10,    11,    -1,    -1,    -1,    15,    65,
      -1,    -1,    -1,    20,   232,    -1,    -1,    -1,     6,    -1,
      -1,     9,    -1,    -1,    -1,   206,   207,    34,    -1,    -1,
      -1,    38,   223,    21,    22,    23,    -1,     6,   219,    -1,
     221,    -1,    -1,    50,    -1,     6,    -1,    -1,    55,    37,
      -1,    58,    59,    60,    61,    62,    63,    18,    46,    47,
      -1,    49,    -1,    24,    25,    26,    27,    -1,    -1,    30,
      39,    -1,    33,    -1,    -1,    -1,    -1,    46,    47,    -1,
      49,    -1,    -1,    -1,    -1,    46,    47,    -1,    49,    -1,
      -1,    -1,    -1,    -1,    -1,    56
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    70,   126,     0,     8,     9,    10,    11,    15,    20,
      34,    38,    50,    55,    58,    59,    60,    61,    62,    63,
      73,    74,    75,    76,    77,    78,    79,    80,    81,    82,
      85,    86,    89,    90,    95,   107,   108,   111,   112,   127,
       3,     3,     5,    83,     3,     3,     3,    64,    71,    71,
      71,    35,    35,     3,    64,    72,    71,    71,    71,    71,
      83,    83,    83,    83,    96,    87,    91,   109,   113,     3,
       6,    84,    97,    98,     9,    21,    22,    23,    37,    46,
      47,    49,    84,    88,    18,    24,    25,    26,    27,    30,
      33,    46,    47,    49,    56,    84,    92,    39,    46,    47,
      49,    84,   110,    44,    45,    84,   114,    46,    47,    83,
      71,    65,    71,    65,    71,    65,    66,    71,    71,     3,
       3,    51,    52,    71,    71,    93,    94,    71,    35,   105,
       3,     3,    51,    52,    71,    57,     3,     3,    51,    52,
      71,   115,   117,   119,     3,     3,   100,    71,    52,    71,
      51,    71,    67,    71,    67,    71,    35,    19,    67,   106,
      52,    71,    51,    71,    52,    71,    51,    71,     3,     7,
      13,    14,   122,   123,   125,     9,    36,    37,    49,    84,
     101,    71,    71,    35,    42,    43,    44,    16,    17,    65,
     103,   104,    71,    71,    71,    71,   116,   118,    12,    65,
     120,   124,   120,     3,   102,    71,    51,    52,    71,    48,
     106,   120,   120,   123,   121,    65,     3,    67,    68,    52,
      71,    51,    71,    99,   120,   124,   124,     3,    71,    71,
      83,    65,   100,   124,    84
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 7:
#line 136 "sg.y"
    { sgSetting("dbhome",(yyvsp[(2) - (2)].string)); }
    break;

  case 8:
#line 139 "sg.y"
    { sgSetting("syslog",(yyvsp[(2) - (2)].string)); }
    break;

  case 9:
#line 142 "sg.y"
    { sgSetting("logdir",(yyvsp[(2) - (2)].string)); }
    break;

  case 10:
#line 145 "sg.y"
    { sgSetting("ldapcachetime",(yyvsp[(2) - (2)].string)); }
    break;

  case 11:
#line 148 "sg.y"
    { sgSetting("ldapprotover",(yyvsp[(2) - (2)].string)); }
    break;

  case 12:
#line 151 "sg.y"
    { sgSetting("ldapbinddn",(yyvsp[(2) - (2)].string)); }
    break;

  case 13:
#line 154 "sg.y"
    { sgSetting("ldapbindpass",(yyvsp[(2) - (2)].string)); }
    break;

  case 14:
#line 157 "sg.y"
    { sgSetting("mysqlusername",(yyvsp[(2) - (2)].string)); }
    break;

  case 15:
#line 160 "sg.y"
    { sgSetting("mysqlpassword",(yyvsp[(2) - (2)].string)); }
    break;

  case 16:
#line 163 "sg.y"
    { sgSetting("mysqldb",(yyvsp[(2) - (2)].string)); }
    break;

  case 19:
#line 174 "sg.y"
    { sgDest((yyvsp[(2) - (2)].string)); }
    break;

  case 20:
#line 178 "sg.y"
    { sgDestEnd();}
    break;

  case 23:
#line 185 "sg.y"
    { sgDestDomainList((yyvsp[(2) - (2)].string)); }
    break;

  case 24:
#line 186 "sg.y"
    { sgDestDomainList(NULL); }
    break;

  case 25:
#line 187 "sg.y"
    { sgDestUrlList((yyvsp[(2) - (2)].string)); }
    break;

  case 26:
#line 188 "sg.y"
    { sgDestUrlList(NULL); }
    break;

  case 27:
#line 189 "sg.y"
    { sgDestExpressionList(NULL,NULL); }
    break;

  case 28:
#line 190 "sg.y"
    { sgDestExpressionList((yyvsp[(3) - (3)].string),"i"); }
    break;

  case 29:
#line 191 "sg.y"
    { sgDestExpressionList((yyvsp[(2) - (2)].string),"n"); }
    break;

  case 30:
#line 192 "sg.y"
    {sgDestRedirect((yyvsp[(2) - (2)].string)); }
    break;

  case 31:
#line 193 "sg.y"
    {sgDestRewrite((yyvsp[(2) - (2)].string)); }
    break;

  case 32:
#line 194 "sg.y"
    { sgDestTime((yyvsp[(2) - (2)].string),WITHIN); }
    break;

  case 33:
#line 195 "sg.y"
    { sgDestTime((yyvsp[(2) - (2)].string),OUTSIDE); }
    break;

  case 34:
#line 196 "sg.y"
    { sgLogFile(SG_BLOCK_DESTINATION,1,0,(yyvsp[(3) - (3)].string)); }
    break;

  case 35:
#line 197 "sg.y"
    { sgLogFile(SG_BLOCK_DESTINATION,0,1,(yyvsp[(3) - (3)].string)); }
    break;

  case 36:
#line 198 "sg.y"
    { sgLogFile(SG_BLOCK_DESTINATION,1,1,(yyvsp[(4) - (4)].string)); }
    break;

  case 37:
#line 199 "sg.y"
    { sgLogFile(SG_BLOCK_DESTINATION,1,1,(yyvsp[(4) - (4)].string)); }
    break;

  case 38:
#line 200 "sg.y"
    { sgLogFile(SG_BLOCK_DESTINATION,0,0,(yyvsp[(2) - (2)].string)); }
    break;

  case 39:
#line 203 "sg.y"
    { sgSource((yyvsp[(2) - (2)].string)); }
    break;

  case 40:
#line 206 "sg.y"
    {sgSourceEnd();}
    break;

  case 45:
#line 215 "sg.y"
    { sgSourceUserList((yyvsp[(2) - (2)].string)); }
    break;

  case 46:
#line 219 "sg.y"
    { sgSourceExecUserList((yyvsp[(2) - (2)].string)); }
    break;

  case 47:
#line 220 "sg.y"
    { sgSourceUserQuota((yyvsp[(2) - (4)].string),(yyvsp[(3) - (4)].string),"3600");}
    break;

  case 48:
#line 221 "sg.y"
    { sgSourceUserQuota((yyvsp[(2) - (4)].string),(yyvsp[(3) - (4)].string),"86400");}
    break;

  case 49:
#line 222 "sg.y"
    { sgSourceUserQuota((yyvsp[(2) - (4)].string),(yyvsp[(3) - (4)].string),"604800");}
    break;

  case 50:
#line 223 "sg.y"
    { sgSourceUserQuota((yyvsp[(2) - (4)].string),(yyvsp[(3) - (4)].string),(yyvsp[(4) - (4)].string));}
    break;

  case 52:
#line 225 "sg.y"
    { sgSourceIpList((yyvsp[(2) - (2)].string)); }
    break;

  case 53:
#line 226 "sg.y"
    { sgSourceTime((yyvsp[(2) - (2)].string),WITHIN); }
    break;

  case 54:
#line 227 "sg.y"
    { sgSourceTime((yyvsp[(2) - (2)].string),OUTSIDE); }
    break;

  case 55:
#line 228 "sg.y"
    {sgLogFile(SG_BLOCK_SOURCE,1,0,(yyvsp[(3) - (3)].string));}
    break;

  case 56:
#line 229 "sg.y"
    {sgLogFile(SG_BLOCK_SOURCE,0,1,(yyvsp[(3) - (3)].string));}
    break;

  case 57:
#line 230 "sg.y"
    {sgLogFile(SG_BLOCK_SOURCE,1,1,(yyvsp[(4) - (4)].string));}
    break;

  case 58:
#line 231 "sg.y"
    {sgLogFile(SG_BLOCK_SOURCE,1,1,(yyvsp[(4) - (4)].string));}
    break;

  case 59:
#line 232 "sg.y"
    { sgLogFile(SG_BLOCK_SOURCE,0,0,(yyvsp[(2) - (2)].string)); }
    break;

  case 60:
#line 233 "sg.y"
    { lastSource->cont_search = 1; }
    break;

  case 62:
#line 236 "sg.y"
    { sgSourceDomain((yyvsp[(2) - (2)].string)); }
    break;

  case 65:
#line 241 "sg.y"
    { sgSourceUser((yyvsp[(2) - (2)].string)); }
    break;

  case 70:
#line 252 "sg.y"
    {sgAcl((yyvsp[(1) - (1)].string),NULL,0);}
    break;

  case 71:
#line 253 "sg.y"
    {sgAcl((yyvsp[(1) - (3)].string),(yyvsp[(3) - (3)].string),WITHIN);}
    break;

  case 72:
#line 254 "sg.y"
    { sgAcl((yyvsp[(1) - (3)].string),(yyvsp[(3) - (3)].string),OUTSIDE); }
    break;

  case 74:
#line 259 "sg.y"
    {sgAcl(NULL,NULL,ELSE);}
    break;

  case 78:
#line 267 "sg.y"
    { }
    break;

  case 79:
#line 268 "sg.y"
    { sgAclSetValue("rewrite",(yyvsp[(2) - (2)].string),0); }
    break;

  case 80:
#line 269 "sg.y"
    { sgAclSetValue("redirect",(yyvsp[(2) - (2)].string),0); }
    break;

  case 81:
#line 270 "sg.y"
    {sgLogFile(SG_BLOCK_ACL,1,0,(yyvsp[(3) - (3)].string));}
    break;

  case 82:
#line 271 "sg.y"
    {sgLogFile(SG_BLOCK_ACL,0,1,(yyvsp[(3) - (3)].string));}
    break;

  case 83:
#line 272 "sg.y"
    {sgLogFile(SG_BLOCK_ACL,1,1,(yyvsp[(4) - (4)].string));}
    break;

  case 84:
#line 273 "sg.y"
    {sgLogFile(SG_BLOCK_ACL,1,1,(yyvsp[(4) - (4)].string));}
    break;

  case 85:
#line 274 "sg.y"
    { sgLogFile(SG_BLOCK_ACL,0,0,(yyvsp[(2) - (2)].string)); }
    break;

  case 87:
#line 278 "sg.y"
    { sgAclSetValue("pass",(yyvsp[(2) - (2)].string),1);}
    break;

  case 88:
#line 279 "sg.y"
    { sgAclSetValue("pass",(yyvsp[(3) - (3)].string),0);}
    break;

  case 90:
#line 283 "sg.y"
    { sgIp((yyvsp[(1) - (1)].string)); }
    break;

  case 91:
#line 286 "sg.y"
    { sgIp((yyvsp[(1) - (1)].string)); }
    break;

  case 93:
#line 289 "sg.y"
    { sgIp("255.255.255.255") ; sgSetIpType(SG_IPTYPE_HOST,NULL,0); }
    break;

  case 94:
#line 290 "sg.y"
    { sgSetIpType(SG_IPTYPE_CIDR,NULL,0); }
    break;

  case 95:
#line 291 "sg.y"
    { sgSetIpType(SG_IPTYPE_CLASS,NULL,0); }
    break;

  case 96:
#line 292 "sg.y"
    { sgSetIpType(SG_IPTYPE_RANGE,NULL,0); }
    break;

  case 98:
#line 296 "sg.y"
    { sgIp((yyvsp[(1) - (1)].string));}
    break;

  case 99:
#line 299 "sg.y"
    { sgRewrite((yyvsp[(2) - (2)].string)); }
    break;

  case 103:
#line 310 "sg.y"
    { sgRewriteSubstitute((yyvsp[(1) - (1)].string)); }
    break;

  case 104:
#line 311 "sg.y"
    { sgRewriteTime((yyvsp[(2) - (2)].string),WITHIN); }
    break;

  case 105:
#line 312 "sg.y"
    { sgRewriteTime((yyvsp[(2) - (2)].string),OUTSIDE); }
    break;

  case 106:
#line 313 "sg.y"
    { sgLogFile(SG_BLOCK_REWRITE,1,0,(yyvsp[(3) - (3)].string)); }
    break;

  case 107:
#line 314 "sg.y"
    { sgLogFile(SG_BLOCK_REWRITE,0,1,(yyvsp[(3) - (3)].string)); }
    break;

  case 108:
#line 315 "sg.y"
    { sgLogFile(SG_BLOCK_REWRITE,1,1,(yyvsp[(4) - (4)].string)); }
    break;

  case 109:
#line 316 "sg.y"
    { sgLogFile(SG_BLOCK_REWRITE,1,1,(yyvsp[(4) - (4)].string)); }
    break;

  case 110:
#line 317 "sg.y"
    { sgLogFile(SG_BLOCK_REWRITE,0,0,(yyvsp[(2) - (2)].string)); }
    break;

  case 111:
#line 321 "sg.y"
    { sgTime((yyvsp[(2) - (2)].string)); }
    break;

  case 115:
#line 332 "sg.y"
    {sgTimeElementInit();}
    break;

  case 116:
#line 333 "sg.y"
    {sgTimeElementAdd((yyvsp[(3) - (3)].string),T_WEEKLY);}
    break;

  case 118:
#line 334 "sg.y"
    {sgTimeElementInit();}
    break;

  case 119:
#line 335 "sg.y"
    {sgTimeElementAdd((yyvsp[(3) - (3)].string),T_WEEKDAY);}
    break;

  case 121:
#line 336 "sg.y"
    {sgTimeElementInit();}
    break;

  case 122:
#line 337 "sg.y"
    {sgTimeElementEnd();}
    break;

  case 123:
#line 340 "sg.y"
    { sgTimeElementClone(); }
    break;

  case 132:
#line 352 "sg.y"
    { sgTimeElementAdd((yyvsp[(1) - (1)].string),T_DVAL);}
    break;

  case 133:
#line 355 "sg.y"
    { sgTimeElementAdd((yyvsp[(1) - (1)].tval),T_TVAL);}
    break;

  case 134:
#line 358 "sg.y"
    { sgTimeElementAdd((yyvsp[(1) - (1)].string),T_DVALCRON);}
    break;


/* Line 1267 of yacc.c.  */
#line 2196 "y.tab.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 385 "sg.y"


#if __STDC__
void sgReadConfig (char *file)
#else
void sgReadConfig (file)
     char *file;
#endif
{
  char *defaultFile=DEFAULT_CONFIGFILE;
  lineno = 1;
  configFile = file;
  if(configFile == NULL)
    configFile = defaultFile;
  yyin = fopen(configFile,"r");
  if(yyin == NULL) 
    sgLogFatal("%s: FATAL: can't open configfile  %s",progname, configFile);
  (void)yyparse();
  if(defaultAcl == NULL)
    sgLogFatal("%s: FATAL: default acl not defined in configfile  %s",
	progname, configFile);
  fclose(yyin);
}


/*
  
  Logfile functions

*/

#if __STDC__
void sgLogFile (int block, int anonymous, int verbose, char *file)
#else
void sgLogFile (block, anonymous, verbose, file)
     int block;
     int anonymous;
     int verbose;
     char *file;
#endif
{
  void **v;
  char *name;
  struct LogFile *p;
  switch(block){
  case(SG_BLOCK_DESTINATION):
    v = (void **) &lastDest->logfile;
    name = lastDest->name;
    break;
  case(SG_BLOCK_SOURCE):
    v = (void **) &lastSource->logfile;
    name = lastSource->name;
    break;
  case(SG_BLOCK_REWRITE):
    v = (void **) &lastRewrite->logfile;
    name = lastRewrite->name;
    break;
  case(SG_BLOCK_ACL):
    v = (void **) &lastAcl->logfile;
    name = lastAcl->name;
    if(strcmp(name,"default")){
      sgLogError("logfile not allowed in acl other than default");
    }
    break;
  default:
    return;
  }
  if(*v == NULL){
    p = (struct LogFile *) sgCalloc(1,sizeof(struct LogFile));
    p->stat = sgLogFileStat(file);
    p->parent_name = name;
    p->parent_type = block;
    p->anonymous = anonymous;
    p->verbose = verbose;
    *v = p;
  } else {
    sgLogError("%s: redefine of logfile %s in line %d",
		    progname,file,lineno);
    return;
  }
}

#if __STDC__
struct LogFileStat *sgLogFileStat(char *file)
#else
struct LogFileStat *sgLogFileStat(file)
     char *file;
#endif
{
  struct LogFileStat *sg;
  struct stat s;
  char buf[MAX_BUF];
  FILE *fd;
  strncpy(buf,file,MAX_BUF);
  if(*file != '/'){
    if(globalLogDir == NULL)
      strncpy(buf,DEFAULT_LOGDIR,MAX_BUF);
    else
      strncpy(buf,globalLogDir,MAX_BUF);
    strcat(buf,"/");
    strcat(buf,file);
  }
  if((fd = fopen(buf, "a")) == NULL){
    sgLogError("%s: can't write to logfile %s",progname,buf);
    return NULL;
  }
  if(stat(buf,&s) != 0){
    sgLogError("%s: can't stat logfile %s",progname,buf);
    return NULL;
  }
  if(LogFileStat == NULL){
    sg = (struct LogFileStat *) sgCalloc(1,sizeof(struct LogFileStat));
    sg->name = sgMalloc(strlen(buf) + 1);
    strcpy(sg->name,buf);
    sg->st_ino = s.st_ino;
    sg->st_dev = s.st_dev;
    sg->fd = fd;
    sg->next = NULL;
    LogFileStat = sg;
    lastLogFileStat = sg;
  } else {
    for(sg = LogFileStat; sg != NULL; sg = sg->next){
      if(sg->st_ino == s.st_ino && sg->st_dev == s.st_dev){
	fclose(fd);
	return sg;
      }
    }
    sg = (struct LogFileStat *) sgCalloc(1,sizeof(struct LogFileStat));
    sg->name = sgMalloc(strlen(buf) + 1);
    strcpy(sg->name,buf);
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
  
  Source functions

*/

#if __STDC__
void sgSource(char *source)
#else
void sgSource(source)
     char *source;
#endif
{
  struct Source *sp;
  if(Source != NULL){
    if((struct Source *) sgSourceFindName(source) != NULL)
      sgLogFatal("%s: source %s is defined in configfile %s",
		      progname,source, configFile);
  }
  sp = (struct Source *)sgCalloc(1,sizeof(struct Source));
  sp->ip=NULL;
  sp->userDb=NULL;
  sp->domainDb=NULL;
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
  sp->next=NULL;
  sp->logfile = NULL;
  sp->name = (char  *) sgCalloc(1,strlen(source) + 1);
  strcpy(sp->name,source);

  if(Source == NULL){
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
 if(s->ip == NULL && s->domainDb == NULL && s->userDb == NULL
       && s->ipDb == NULL
       && s->ldapuserurlcount == 0 && s->ldapipurlcount == 0 ){
   sgLogError("sourceblock %s missing active content, set inactive",s->name);
   s->time = NULL;
   s->active = 0;
 }
}
#else
void sgSourceEnd()
{
 struct Source *s;
 s = lastSource;
 if(s->ip == NULL && s->domainDb == NULL && s->userDb == NULL){
   sgLogError("sourceblock %s missing active content, set inactive",s->name);
   s->time = NULL;
   s->active = 0;
 }
}
#endif

#if __STDC__
void sgSourceUser(char *user)
#else
void sgSourceUser(user)
     char *user;
#endif
{
  struct Source *sp;
  char *lc;
  sp = lastSource;
  if(sp->userDb == NULL){
    sp->userDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
    sp->userDb->type=SGDBTYPE_USERLIST;
    sgDbInit(sp->userDb,NULL);
  }
  for(lc=user; *lc != '\0'; lc++) /* convert username to lowercase chars */
    *lc = tolower(*lc);
  sgDbUpdate(sp->userDb, user, (char *) setuserinfo(),
            sizeof(struct UserInfo));
// DEBUG
  sgLogError("Added User: %s", user);
}

#if __STDC__
void sgSourceUserList(char *file)
#else
void sgSourceUserList(file)
     char *file;
#endif
{
  char *dbhome = NULL, *f;
  FILE *fd;
  char line[MAX_BUF];
  char *p,*c,*s,*lc;
  int l=0;
  struct Source *sp;
  sp = lastSource;
  if(sp->userDb == NULL){
    sp->userDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
    sp->userDb->type=SGDBTYPE_USERLIST;
    sgDbInit(sp->userDb,NULL);
  }
  dbhome = sgSettingGetValue("dbhome");
  if(dbhome == NULL)
    dbhome = DEFAULT_DBHOME;
  if (file[0] == '/') {
    f = strdup(file);
  } else {
    f = (char  *) sgCalloc(1,strlen(dbhome) + strlen(file) + 5);
    strcpy(f,dbhome);
    strcat(f,"/");
    strcat(f,file);
  }
  if((fd = fopen(f,"r")) == NULL){
    sgLogError("%s: can't open userlist %s: %s",progname, f,strerror(errno));
    return;
  }
  while(fgets(line,sizeof(line),fd) != NULL){
    l++;
    if(*line == '#')
      continue;
    p = strchr(line,'\n');
    if(p != NULL && p != line){
      if(*(p - 1) == '\r') /* removing ^M  */
	p--;
      *p = '\0';
    }
    c = strchr(line,'#');
    p = strtok(line," \t,");
    if((s = strchr(line,':')) != NULL){
      *s = '\0';
      for(lc=line; *lc != '\0'; lc++) /* convert username to lowercase chars */
	*lc = tolower(*lc);
      sgDbUpdate(sp->userDb, line, (char *) setuserinfo(),
                sizeof(struct UserInfo));
    } else {
      do {
	if(c != NULL && p >= c) /*find the comment */
	  break;
	for(lc=p; *lc != '\0'; lc++) /* convert username to lowercase chars */
	  *lc = tolower(*lc);
       sgDbUpdate(sp->userDb, p, (char *) setuserinfo(),
                  sizeof(struct UserInfo));
// DEBUG
        sgLogError("Added UserList source: %s", p);
      } while((p=strtok(NULL," \t,")) != NULL);
    }
  }
  fclose(fd);
}


/* MySQLsupport */
#ifdef HAVE_MYSQL
#if __STDC__
void sgSourceUserQuery(char *query)
#else
void sgSourceUserQuery(query)
     char *query;
#endif
{
  char *dbhome = NULL, *f;
  MYSQL *conn;
  MYSQL_RES *res;
  MYSQL_ROW *row;
  char line[MAX_BUF];
  char *my_query, *my_user, *my_pass, *my_db;
  char *str=";";
  int l=0;
  struct Source *sp;
  sp = lastSource;
  if(sp->userDb == NULL){
    sp->userDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
    sp->userDb->type=SGDBTYPE_USERLIST;
    sgDbInit(sp->userDb,NULL);
  }
  dbhome = sgSettingGetValue("dbhome");
  my_user = sgSettingGetValue("mysqlusername");
  my_pass = sgSettingGetValue("mysqlpassword");
  my_db = sgSettingGetValue("mysqldb");
  if(dbhome == NULL) {
    dbhome = DEFAULT_DBHOME;
  }
  if( !(conn = mysql_init(0)) ) {
     sgLogError("%s: can't open userquery: mysql init",progname); 
    return;
  }
  if( ! mysql_real_connect(conn, "localhost", my_user, my_pass, my_db,
      0,NULL,0) ) {
     sgLogError("%s: can't open userquery: mysql connect",progname); 
    return;
  }
  my_query=(char *)calloc(strlen(query) + strlen(str) + 1,sizeof(char));
  strcat(my_query, query);
  strcat(my_query, str);
  /* DEBUG:   sgLogError("%s: TEST: MySQL Query %s",progname,my_query);  */
  if( mysql_query(conn, my_query) ) {
     sgLogError("%s: can't open userquery: mysql query",progname); 
    return;
  }
  res = mysql_use_result(conn);
  while( row = mysql_fetch_row(res) ) {
    strncpy(line, row[0], sizeof(line)-1);
    l++;
    sgDbUpdate(sp->userDb, line, (char *) setuserinfo(), sizeof(struct UserInfo));
     sgLogError("Added MySQL source: %s", line); 
  }
  mysql_free_result(res);
  mysql_close(conn);
 }
#endif


/* LDAP Support */
#ifdef HAVE_LIBLDAP
#if __STDC__
void sgSourceLdapUserSearch(char *url)
#else
void sgSourceLdapUserSearch(url)
     char *url;
#endif
{
  struct Source *sp;
  sp = lastSource;

/*  DEBUG
  sgLogError("sgSourceLdapUserSearch called with: %s", url);
*/

  if(!ldap_is_ldap_url(url)) {
     sgLogError("%s: can't parse LDAP url %s",progname, url);  
    return;
  }

  /* looks ok, add the url to the source object url array */
  sp->ldapuserurls = (char**) sgRealloc(sp->ldapuserurls,
                              sizeof(char*) * (sp->ldapuserurlcount+1));
  sp->ldapuserurls[sp->ldapuserurlcount] = (char*) sgMalloc(strlen(url) + 1);
  strcpy(sp->ldapuserurls[sp->ldapuserurlcount], url);
  sp->ldapuserurlcount++;

  /* create a userDb if it doesn't exist, since we'll need it later
   * for caching */
  if(sp->userDb == NULL){
    sp->userDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
    sp->userDb->type=SGDBTYPE_USERLIST;
    sgDbInit(sp->userDb,NULL);
  }
}
#if __STDC__
void sgSourceLdapIpSearch(char *url)
#else
void sgSourceLdapIpSearch(url)
     char *url;
#endif
{
  struct Source *sp;
  sp = lastSource;

    sgLogError("DEBUG: sgSourceLdapIpSearch called with: %s", url); 

  if(!ldap_is_ldap_url(url)) {
    sgLogError("%s: can't parse LDAP url %s",progname, url);
    return;
  }

  /* looks ok, add the url to the source object url array */
  sp->ldapipurls = (char**) sgRealloc(sp->ldapipurls,
                                    sizeof(char*) * (sp->ldapipurlcount+1));
  sp->ldapipurls[sp->ldapipurlcount] = (char*) sgMalloc(strlen(url) + 1);
  strcpy(sp->ldapipurls[sp->ldapipurlcount], url);
  sp->ldapipurlcount++;

  /* create a ipDb if it doesn't exist, since we'll need it later
   * for caching */
  if(sp->ipDb == NULL){
    sp->ipDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
    sp->ipDb->type=SGDBTYPE_USERLIST;
    sgDbInit(sp->ipDb,NULL);
  }
}
#endif

#if __STDC__
void sgSourceExecUserList(char *cmd)
#else
void sgSourceExecUserList(cmd)
     char *cmd;
#endif
{
  FILE *pInput;
  char buffer[100];
  struct Source *sp;
  char *lc;
  sp = lastSource;
  if(sp->userDb == NULL){
    sp->userDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
    sp->userDb->type=SGDBTYPE_USERLIST;
    sgDbInit(sp->userDb,NULL);
  }

/*  DEBUG
  sgLogError("sgSourceExecUserList called with: %s", cmd);
*/

  pInput = popen(cmd, "r");
  if(pInput == NULL) {
    sgLogError("%s: Unable to run execuserlist command: %s", progname, cmd);
    return;
  }

  while(fgets(buffer, sizeof(buffer), pInput) != NULL) {
    char *sc;
    /* skip leading whitespace */
    for(sc=buffer; *sc != '\0' && isspace(*sc); sc++)
    ;
    /* convert username to lowercase */
    for(lc=sc; *lc != '\0'; lc++)
      *lc = tolower(*lc);
    /* remove newline and trailing whitespace */
    while(lc>=sc && (*lc=='\0' || isspace(*lc)))
      *lc-- = '\0';
    if(lc >= sc) {
      sgDbUpdate(sp->userDb, sc, (char *) setuserinfo(),
                 sizeof(struct UserInfo));
       sgLogError("Added exec source: %s", sc); 
    }
  }

  pclose(pInput);
}



#if __STDC__
void sgSourceUserQuota(char *seconds, char *sporadic, char *renew)
#else
void sgSourceUserQuota(seconds, sporadic, renew)
     char *seconds;
     char *sporadic;
     char *renew;
#endif
{
  int s;
  struct UserQuota *uq;
  struct Source *sp;
  sp = lastSource;
  uq = &sp->userquota;
  s = atoi(seconds);
  if(s <= 0)
    sgLogError("Userquota seconds sporadic hourly|daily|weekly");
  uq->seconds = s; 
  s = atoi(sporadic);
  if(s <= 0)
    sgLogError("Userquota seconds sporadic hourly|daily|weekly");
  uq->sporadic = s; 
  s = atoi(renew);
  if(s <= 0)
    sgLogError("Userquota seconds sporadic hourly|daily|weekly");
  uq->renew = s;
}


#if __STDC__
void sgSourceDomain(char *domain)
#else
void sgSourceDomain(domain)
     char *domain;
#endif
{
  struct Source *sp;
  sp = lastSource;
  if(sp->domainDb == NULL){
    sp->domainDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
    sp->domainDb->type=SGDBTYPE_DOMAINLIST;
    sgDbInit(sp->domainDb,NULL);
  }
  sgDbUpdate(sp->domainDb,domain, NULL, 0);
}

#if __STDC__
void sgSourceTime(char *name, int within)
#else
void sgSourceTime(name, within)
     char *name;
     int within;
#endif
{
  struct Time *time = NULL;
  struct Source *sp;
  sp = lastSource;
  if((time = sgTimeFindName(name)) == NULL){
    sgLogFatal("%s: FATAL: Time %s is not defined in configfile %s",
		    progname,name, configFile);
  }
  sp->within = within;
  sp->time = time;
}

#if __STDC__
struct Source *sgSourceFindName(char *name)
#else
struct Source *sgSourceFindName(name)
     char *name;
#endif
{
  struct Source *p;
  for(p=Source; p != NULL; p = p->next){
    if(!strcmp(name,p->name))
      return p;
  }
  return NULL;
}

#if __STDC__
void sgSourceIpList(char *file)
#else
void sgSourceIpList(file)
     char *file;
#endif
{
  char *dbhome = NULL, *f;
  FILE *fd;
  char line[MAX_BUF];
  char *p,*c,*cidr;
  int i,l=0;
  dbhome = sgSettingGetValue("dbhome");
  if(dbhome == NULL)
    dbhome = DEFAULT_DBHOME;
  if (file[0] == '/') {
    f = strdup(file);
  } else {
    f = (char  *) sgCalloc(1,strlen(dbhome) + strlen(file) + 5);
    strcpy(f,dbhome);
    strcat(f,"/");
    strcat(f,file);
  }
  if((fd = fopen(f,"r")) == NULL){
    sgLogError("%s: can't open iplist %s: %s",progname, f,strerror(errno));
    return;
  }
  sgLogError("init iplist %s",f);
  while(fgets(line,sizeof(line),fd) != NULL){
    l++;
    if(*line == '#')
      continue;
    p = strchr(line,'\n');
    if(p != NULL && p != line){
      if(*(p - 1) == '\r') /* removing ^M  */
	p--;
      *p = '\0';
    }
    c = strchr(line,'#');
    p = strtok(line," \t,");
    do {
      if(c != NULL && p >= c) /*find the comment */
	break;
      i=strspn(p,".0123456789/-");
      if(i == 0)
	break;
      *(p + i ) = '\0';
      if((cidr = strchr(p,'/')) != NULL){
	*cidr = '\0';
	cidr++;
	sgIp(p);
	sgIp(cidr);
	if(strchr(cidr,'.') == NULL)
	  sgSetIpType(SG_IPTYPE_CIDR,f,l);
	else 
	  sgSetIpType(SG_IPTYPE_CLASS,f,l);
      } else if((cidr = strchr(p,'-')) != NULL) {
	*cidr = '\0';
	cidr++;
	sgIp(p);
	sgIp(cidr);
	sgSetIpType(SG_IPTYPE_RANGE,f,l);
      } else {
	sgIp(p);
	sgIp(strdup("255.255.255.255"));
	sgSetIpType(SG_IPTYPE_HOST,f,l);
      }
    } while((p=strtok(NULL," \t,")) != NULL);
  }
  fclose(fd);
}

/*
  

 */

#if __STDC__
struct Source *sgFindSource (struct Source *bsrc, 
			     char *net, char *ident, char *domain)
#else
struct Source *sgFindSource (bsrc, net, ident, domain)
     struct Source *bsrc;
     char *net;
     char *ident;
     char *domain;
#endif
{
/* DEBUG
  sgLogError("DEBUG: sgfindsource  called with: %s", net);
*/
  struct Source *s;
  struct Ip *ip;
  int foundip, founduser, founddomain, unblockeduser;
  unsigned long i, octet = 0, *op;
  struct UserInfo *userquota;
  char *dotnet;
#ifdef HAVE_LIBLDAP
  int unblockedip;
  struct IpInfo *ipquota;
#endif
  if(net != NULL){
    dotnet = (char*) sgMalloc(strlen(net) + 1);
    strcpy(dotnet, net);
    op = sgConvDot(net);
    if(op != NULL)
      octet = *op;
  }
  for(s=bsrc; s != NULL; s = s->next){
    foundip = founduser = founddomain = 0;
    unblockeduser = 1;
    if(s->active == 0)
      continue;
    if(s->ip != NULL){
      if(net == NULL)
	foundip = 0;
      else {
	for(ip=s->ip; ip != NULL; ip = ip->next){
	  if(ip->net_is_set == 0)
	    continue;
	  if(ip->type == SG_IPTYPE_RANGE){
	    if(octet >= ip->net && octet <= ip->mask){
	      foundip = 1;
	      break;
	    }
	  } else { /* CIDR or HOST */
	    i = octet & ip->mask;
	    if(i == ip->net){
	      foundip = 1;
	      break;
	    }
	  }
	}
      }
    } else
#ifdef HAVE_LIBLDAP 
// debut ip
      if( s->ipDb != NULL){
      if(dotnet == NULL)
       foundip = 0;
      else {
//        rfc1738_unescape(dotnet);
        if(sgFindIp(s, dotnet, &ipquota)) {
         foundip = 1;
         unblockedip = 1;
         if(s->ipquota.seconds != 0){
            struct IpInfo uq;
           time_t t = time(NULL) + globalDebugTimeDelta;
           sgLogError("status %d time %d lasttime %d consumed %d", ipquota->status, ipquota->time, ipquota->last, ipquota->consumed);
           sgLogError("renew %d seconds %d", s->ipquota.renew, s->ipquota.seconds);
           if(ipquota->status == 0){ //first time
             ipquota->status = 1;
             ipquota->time = t;
             ipquota->last = t;
             sgLogError("ip %s first time %d", dotnet, ipquota->time);
           } else if(ipquota->status == 1){
             sgLogError("ip %s other time %d %d",dotnet,ipquota->time,t);
             if(s->ipquota.sporadic > 0){
               if(t - ipquota->last  < s->ipquota.sporadic){
                 ipquota->consumed += t - ipquota->last;
                 ipquota->time = t;
               }
               if(ipquota->consumed > s->ipquota.seconds){
                 ipquota->status = 2; // block this ip, time is up
                 unblockedip = 0;
               }
               ipquota->last = t;
               sgLogError("ip %s consumed %d %d",dotnet,ipquota->consumed, ipquota->last);
             } else if(ipquota->time + s->ipquota.seconds < t){
               sgLogError("time is up ip %s blocket", net);
               ipquota->status = 2; // block this ip, time is up
               unblockedip = 0;
             } 
           } else {
             sgLogError("ip %s blocket %d %d %d %d", dotnet, ipquota->status, ipquota->time, t, (ipquota->time + s->ipquota.renew) - t);
             if(ipquota->time + s->ipquota.renew < t){ // new chance
               sgLogError("ip %s new chance", net);
               unblockedip = 1;
               ipquota->status = 1;
               ipquota->time = t;
               ipquota->consumed = 0;
             } else 
               unblockedip = 0;
           }
           sgDbUpdate(s->ipDb, dotnet, (void *) ipquota, 
                      sizeof(struct IpInfo));
         }
       }
      }
    } else
#endif
//fin ip
      foundip = 1;
      if(s->userDb != NULL){
      if(*ident == '\0')
	founduser = 0;
      else {
#ifdef HAVE_LIBLDAP
        if(sgFindUser(s, ident, &userquota)) {
#else
        rfc1738_unescape(ident);
        if(defined(s->userDb, ident, (char **) &userquota) == 1){
#endif
	  founduser = 1;
	  unblockeduser = 1;
	  if(s->userquota.seconds != 0){
            struct UserInfo uq;
	    time_t t = time(NULL) + globalDebugTimeDelta;
	    //sgLogError("status %d time %d lasttime %d consumed %d", userquota->status, userquota->time, userquota->last, userquota->consumed);
	    //sgLogError("renew %d seconds %d", s->userquota.renew, s->userquota.seconds);
	    if(userquota->status == 0){ //first time
	      userquota->status = 1;
	      userquota->time = t;
	      userquota->last = t;
	      //sgLogError("user %s first time %d", ident, userquota->time);
	    } else if(userquota->status == 1){
	      //sgLogError("user %s other time %d %d",ident,userquota->time,t);
	      if(s->userquota.sporadic > 0){
		if(t - userquota->last  < s->userquota.sporadic){
		  userquota->consumed += t - userquota->last;
		  userquota->time = t;
		}
		if(userquota->consumed > s->userquota.seconds){
		  userquota->status = 2; // block this user, time is up
		  unblockeduser = 0;
		}
		userquota->last = t;
		//sgLogError("user %s consumed %d %d",ident,userquota->consumed, userquota->last);
	      } else if(userquota->time + s->userquota.seconds < t){
		sgLogError("time is up user %s blocket", ident);
		userquota->status = 2; // block this user, time is up
		unblockeduser = 0;
	      } 
	    } else {
	      //sgLogError("user %s blocket %d %d %d %d", ident, userquota->status, userquota->time, t, (userquota->time + s->userquota.renew) - t);
	      if(userquota->time + s->userquota.renew < t){ // new chance
		//sgLogError("user %s new chance", ident);
		unblockeduser = 1;
		userquota->status = 1;
		userquota->time = t;
		userquota->consumed = 0;
	      } else 
		unblockeduser = 0;
	    }
	    sgDbUpdate(s->userDb, ident, (void *) userquota, 
                      sizeof(struct UserInfo));
	  }
	}
      }
    } else
      founduser = 1;
    if(s->domainDb != NULL){
      if(*domain == '\0')
	founddomain = 0;
      else {
	if(defined(s->domainDb, domain, (char **) NULL) == 1)
	  founddomain = 1;
      }
    } else
      founddomain = 1;
    if(founduser && foundip && founddomain){
      if(unblockeduser)
	return s;
      else {
	lastActiveSource = s;
	return NULL;
      }
    }
  }
  return NULL;
}



/*destination block funtions */

#if __STDC__
void sgDest(char *dest)
#else
void sgDest(dest)
     char *dest;
#endif
{
  struct Destination *sp;
  if(Dest != NULL){
    if((struct Destination *) sgDestFindName(dest) != NULL)
      sgLogFatal("%s: destination %s is defined in configfile %s",
		   progname,dest, configFile);
  }
  sp = (struct Destination *) sgCalloc(1,sizeof(struct Destination));
  sp->domainlist=NULL;
  sp->urllist=NULL;
  sp->expressionlist=NULL;
  sp->redirect=NULL;
  sp->rewrite=NULL;
  sp->active = 1;
  sp->time = NULL;
  sp->within = 0;
  sp->logfile = NULL;
  sp->next=NULL;
  sp->name = (char  *) sgCalloc(1,strlen(dest) + 1);
  strcpy(sp->name,dest);

  if(Dest == NULL){
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
 if(d->domainlist == NULL && d->urllist == NULL && d->expressionlist == NULL
    && d->redirect == NULL && d->rewrite == NULL){
   sgLogError("destblock %s missing active content, set inactive",d->name);
   d->time = NULL;
   d->active = 0;
 }
}

#if __STDC__
void sgDestDomainList(char *domainlist)
#else
void sgDestDomainList(domainlist)
     char *domainlist;
#endif
{
  struct Destination *sp;
  char *dbhome = NULL, *dl = domainlist, *name;
  dbhome = sgSettingGetValue("dbhome");
  sp = lastDest;
  if(dbhome == NULL)
    dbhome = DEFAULT_DBHOME;
 if(domainlist == NULL){
    name = sp->name;
    dl = (char *) sgCalloc(1,strlen("/dest/") + strlen(name) + strlen("/domainlist"));
    strcpy(dl,"/dest/");
    strcat(dl,name);
    strcat(dl,"/domainlist");
    sp->domainlist = (char  *) sgCalloc(1,strlen(dbhome) + strlen("/") + strlen(dl) + 4);
    strcpy(sp->domainlist,dbhome);
    strcat(sp->domainlist,"/");
    strcat(sp->domainlist,dl);
    sgFree(dl);
  } else {
    if (domainlist[0] == '/') {
      sp->domainlist = strdup(domainlist);
    } else {
    sp->domainlist = (char  *) sgCalloc(1,strlen(dbhome) + strlen("/") + strlen(domainlist) + 4);
    strcpy(sp->domainlist,dbhome);
    strcat(sp->domainlist,"/");
    strcat(sp->domainlist,domainlist);
    }
  }
  sp->domainlistDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
  sp->domainlistDb->type=SGDBTYPE_DOMAINLIST;
  sgLogError("init domainlist %s",sp->domainlist);
  sgDbInit(sp->domainlistDb,sp->domainlist);
  if(sp->domainlistDb->entries == 0) { /* empty database */
    sgLogError("domainlist empty, removed from memory");
    sgFree(sp->domainlistDb);
    sp->domainlistDb = NULL;
  }
}

#if __STDC__
void sgDestUrlList(char *urllist)
#else
void sgDestUrlList(urllist)
     char *urllist;
#endif
{
  struct Destination *sp;
  char *dbhome = NULL, *dl = urllist, *name;
  dbhome = sgSettingGetValue("dbhome");
  sp = lastDest;
  if(dbhome == NULL)
    dbhome = DEFAULT_DBHOME;
  if(urllist == NULL){
    name = sp->name;
    dl = (char *) sgCalloc(1,strlen("/dest/") + strlen(name) + strlen("/urllist"));
    strcpy(dl,"/dest/");
    strcat(dl,name);
    strcat(dl,"/urllist");
    sp->urllist = (char  *) sgCalloc(1,strlen(dbhome) + strlen("/") + strlen(dl) + 4);
    strcpy(sp->urllist,dbhome);
    strcat(sp->urllist,"/");
    strcat(sp->urllist,dl);
    sgFree(dl);
  } else {
    if (urllist[0] == '/') {
      sp->urllist = strdup(urllist);
    } else {
    sp->urllist = (char  *) sgCalloc(1,strlen(dbhome) + strlen("/") + strlen(urllist) + 4);
    strcpy(sp->urllist,dbhome);
    strcat(sp->urllist,"/");
    strcat(sp->urllist,urllist);
    }
  }
  sp->urllistDb = (struct sgDb *) sgCalloc(1,sizeof(struct sgDb));
  sp->urllistDb->type=SGDBTYPE_URLLIST;
  sgLogError("init urllist %s",sp->urllist);
  sgDbInit(sp->urllistDb,sp->urllist);
  if(sp->urllistDb->entries == 0) { /* empty database */
    sgLogError("urllist empty, removed from memory");
    sgFree(sp->urllistDb);
    sp->urllistDb = NULL;
  }
}

#if __STDC__
void sgDestExpressionList(char *exprlist, char *chcase)
#else
void sgDestExpressionList(exprlist, chcase)
     char *exprlist;
     char *chcase;
#endif
{
  FILE *fp;
  char buf[MAX_BUF],errbuf[256];
  struct Destination *sp;
  struct sgRegExp *regexp;
  char *dbhome = NULL, *dl = exprlist, *name, *p;
  int flags = REG_EXTENDED;
  dbhome = sgSettingGetValue("dbhome");
  sp = lastDest;
  if(dbhome == NULL)
    dbhome = DEFAULT_DBHOME;
  if(exprlist == NULL){
    name = sp->name;
    dl = (char *) sgCalloc(1,strlen("/dest/") +strlen(name) + strlen("/expressionlist"));
    strcpy(dl,"/dest/");
    strcat(dl,name);
    strcat(dl,"/expressionlist");
    flags |= REG_ICASE; /* default case insensitive */
    sp->expressionlist = (char  *) sgCalloc(1,strlen(dbhome)+strlen(dl)+10);
    strcpy(sp->expressionlist,dbhome);
    strcat(sp->expressionlist,"/");
    strcat(sp->expressionlist,dl);
    sgFree(dl);
  } else {
    if (exprlist[0] == '/') {
      sp->expressionlist = strdup(exprlist);
    } else {
    sp->expressionlist = (char  *) sgCalloc(1,strlen(dbhome) + strlen("/") + strlen(exprlist) + 4);
    strcpy(sp->expressionlist,dbhome);
    strcat(sp->expressionlist,"/");
    strcat(sp->expressionlist,exprlist);
    }
    if(strncmp(chcase,"c",1))
          flags |= REG_ICASE; /* set case insensitive */
  }
  sgLogError("init expressionlist %s",sp->expressionlist);
  if ((fp = fopen(sp->expressionlist, "r")) == NULL) 
    sgLogFatal("%s: %s", sp->expressionlist, strerror(errno));
  while(fgets(buf, sizeof(buf), fp) != NULL){
    p = (char *) strchr(buf,'\n');
    if(p != NULL && p != buf){
      if(*(p - 1) == '\r') /* removing ^M  */
	p--;
      *p = '\0';
    }
    regexp=sgNewPatternBuffer(buf,flags);
    if(regexp->error){
      regerror(regexp->error,regexp->compiled, errbuf,sizeof(errbuf));
      sgLogError("%s: %s", sp->expressionlist, strerror(errno));
    }
    if(lastDest->regExp == NULL){
      lastDest->regExp = regexp;
      lastRegExpDest = regexp;
    } else {
      lastRegExpDest->next = regexp;
      lastRegExpDest = regexp;
    }
  }
  fclose(fp);
}

#if __STDC__
void sgDestRedirect(char *value)
#else
void sgDestRedirect(value)
     char *value;
#endif
{
  struct Destination *sp;
  sp = lastDest;
  sp->redirect = (char *) sgCalloc(1,strlen(value) + 1);
  strcpy(sp->redirect,value);
}

void sgDestRewrite(char *value){
  struct sgRewrite *rewrite = NULL;
  struct Destination *sp;
  sp = lastDest;
  if((rewrite = sgRewriteFindName(value)) == NULL){
    sgLogFatal("%s: FATAL: Rewrite %s is not defined in configfile %s",
		    progname,value, configFile);
  }
  sp->rewrite = rewrite;
}

#if __STDC__
int sgRegExpMatch(struct sgRegExp *regexp, char *str)
#else
int sgRegExpMatch(regexp, str)
     struct sgRegExp *regexp;
     char *str;
#endif
{
  struct sgRegExp *rp;
  static char errbuf[256];
  int error;
  for(rp = regexp; rp != NULL; rp = rp->next){
    error = regexec(rp->compiled, str, 0,0,0);
    if(error != 0 && error != REG_NOMATCH) {
      regerror(error,rp->compiled, errbuf,sizeof(errbuf));
      sgLogError("Error in regex %30.30s %-60.60s  %d %s\n",rp->pattern,str,error,errbuf);
    }
    if(error == 0) /* match */
      return 1;
  }
  return 0;
}

#if __STDC__
void sgDestTime(char *name, int within)
#else
void sgDestTime(name, within)
     char *name;
     int within;
#endif
{
  struct Time *time = NULL;
  struct Destination *sp;
  sp = lastDest;
  if((time = sgTimeFindName(name)) == NULL){
    sgLogFatal("%s: FATAL: Time %s is not defined in configfile %s",
		    progname,name, configFile);
  }
  sp->within = within;
  sp->time = time;
}

#if __STDC__
struct Destination *sgDestFindName(char *name)
#else
struct Destination *sgDestFindName(name)
     char *name;
#endif
{
  struct Destination *p;
  for(p=Dest; p != NULL; p = p->next){
    if(!strcmp(name,p->name))
      return p;
  }
  return NULL;
}

/*
  Setting functions
*/


#if __STDC__
void sgSetting(char *name, char *value)
#else
void sgSetting(name, value)
     char *name;
     char *value;
#endif
{
  struct Setting *sp;
  if(Setting != NULL){
    if((struct Setting *) sgSettingFindName(name) != NULL)
      sgLogFatal("%s: setting %s is defined in configfile %s",
		      progname,name, configFile);
  }
  sp = (struct Setting *) sgCalloc(1,sizeof(struct Setting));

  sp->name = strdup(name);
  sp->value = strdup(value);

// DEBUG
  if(strcmp(name,"ldapbindpass") == 0 || strcmp(name,"mysqlpassword") == 0) {
     sgLogError("New setting: %s: ***************", name);
  }
  else { 
     sgLogError("New setting: %s: %s", name, value);
  }

  if(Setting == NULL){
    Setting = sp;
    lastSetting = sp;
  } else {
    lastSetting->next = sp;
    lastSetting = sp;
  }
  if(!strcmp(name,"logdir")){
    globalLogDir= strdup(value);
  }
#ifdef USE_SYSLOG
  if(!strcmp(name,"syslog")){
    sgSyslogSetting(value);
  }
#endif
}

#ifdef USE_SYSLOG
#if __STDC__
void sgSyslogSetting (char *value)
#else
void sgSyslogSetting (value)
    char *value;
#endif
{
    if (strcmp(value,"enable") == 0){
        //printf(">> enable syslog option\n");
        globalSyslog = 1;
    }
    else if (strcmp(value,"disable") == 0){
        //printf(">> disable syslog option \n");
        globalSyslog = 0;
    }
    else {
        //printf(">> invalid syslog config option \n");
        sgLogFatal("Invalid syslog option in %s line %d \n", configFile, lineno);
    }
}
#endif


#if __STDC__
struct Setting *sgSettingFindName(char *name)
#else
struct Setting *sgSettingFindName(name)
     char *name;
#endif
{
  struct Setting *p;
  for(p=Setting; p != NULL; p = p->next){
    if(!strcmp(name,p->name))
      return p;
  }
  return NULL;
}


#if __STDC__
char *sgSettingGetValue(char *name)
#else
char *sgSettingGetValue(name)
     char *name;
#endif
{
  struct Setting *p;
  p = sgSettingFindName(name);
  if(p != NULL)
    return p->value;
  return NULL;
}


/*
  
  sgRewrite function

 */

#if __STDC__
void sgRewrite(char *rewrite)
#else
void sgRewrite(rewrite)
     char *rewrite;
#endif
{
  struct sgRewrite *rew;
  if(Rewrite != NULL){
    if((struct sgRewrite *) sgRewriteFindName(rewrite) != NULL)
      sgLogFatal("%s: rewrite %s is defined in configfile %s",
		      progname,rewrite, configFile);
  }
  rew = (struct sgRewrite *) sgCalloc(1,sizeof(struct sgRewrite));
  rew->name = strdup(rewrite);
  rew ->rewrite = NULL;
  rew->logfile = NULL;
  rew->time = NULL;
  rew->active = 1;
  rew->within = 0;
  rew->next=NULL;

  if(Rewrite == NULL){
    Rewrite = rew;
    lastRewrite = rew;
  } else {
    lastRewrite->next = rew;
    lastRewrite = rew;
  }
}

#if __STDC__
void sgRewriteTime(char *name, int within)
#else
void sgRewriteTime(name, within)
     char *name;
     int within;
#endif
{
  struct Time *time = NULL;
  struct sgRewrite *sp;
  sp = lastRewrite;
  if((time = sgTimeFindName(name)) == NULL){
    sgLogFatal("%s: FATAL: Time %s is not defined in configfile %s",
		    progname,name, configFile);
  }
  sp->within = within;
  sp->time = time;
}

#if __STDC__
void sgRewriteSubstitute (char *string)
#else
void sgRewriteSubstitute (string)
     char *string;
#endif
{
  char *pattern, *subst = NULL , *p;
  int flags = REG_EXTENDED ;
  int global = 0;
  char *httpcode = NULL;
  struct sgRegExp *regexp;
  char errbuf[256];
  pattern = string + 2 ; /* skipping s@ */
  p = pattern;
  while((p = strchr(p,'@')) != NULL){
    if(*( p - 1) != '\\'){
      *p = '\0';
      subst = p + 1;
      break;
    }
    p++;
  }
  p= strrchr(subst,'@');
  while(p != NULL && *p != '\0'){
    if(*p == 'r' )
      httpcode =  REDIRECT_TEMPORARILY;
    if(*p == 'R' )
      httpcode =  REDIRECT_PERMANENT;
    if(*p == 'i' || *p == 'I')
      flags |= REG_ICASE;
    if(*p == 'g')
      global = 1;
    *p = '\0'; /*removes @i from string */
    p++;
  } 
  regexp=sgNewPatternBuffer(pattern,flags);
  if(regexp->error){
      regerror(regexp->error,regexp->compiled, errbuf,sizeof(errbuf));
      sgLogError("Error in regexp %s: %s",pattern,errbuf);
  } else {
    regexp->substitute = strdup(subst);
  }
  if(lastRewrite->rewrite == NULL)
    lastRewrite->rewrite = regexp;
  else 
    lastRewriteRegExec->next=regexp;
  regexp->httpcode = httpcode;
  regexp->global = global;
  lastRewriteRegExec = regexp;
}

#if __STDC__
char *sgRewriteExpression(struct sgRewrite *rewrite, char *subst)
#else
char *sgRewriteExpression(rewrite, subst)
     struct sgRewrite *rewrite;
     char *subst;
#endif
{
  char *result = NULL;
  result = sgRegExpSubst(rewrite->rewrite, subst);
  return result;
}

#if __STDC__
struct sgRewrite *sgRewriteFindName(char *name)
#else
struct sgRewrite *sgRewriteFindName(name)
     char *name;
#endif
{
  struct sgRewrite *p;
  for(p=Rewrite; p != NULL; p = p->next){
    if(!strcmp(name,p->name))
      return p;
  }
  return NULL;
}



/*
  Time functions
*/

#if __STDC__
void sgTime(char *name)
#else
void sgTime(name)
     char *name;
#endif
{
  struct Time *t;
  if(Time != NULL){
    if((struct Time *) sgTimeFindName(name) != NULL)
      sgLogFatal("%s: time %s is defined in configfile %s",
		      progname,name, configFile);
  } else 
    numTimeElements = 0;
  t = (struct Time *) sgCalloc(1,sizeof(struct Time));
  t->name = strdup(name);
  t->element = NULL;
  t->active = 1;
  TimeElement = NULL;
  lastTimeElement = NULL;
  if(Time == NULL){
    Time = t;
    lastTime = t;
  } else {
    lastTime->next = t;
    lastTime = t;
  }
}

#if __STDC__
void sgTimeElementInit()
#else
void sgTimeElementInit()
#endif
{
  struct TimeElement *te;
  te = (struct TimeElement *) sgCalloc(1,sizeof(struct TimeElement));
  numTimeElements++;
  if(lastTime->element == NULL)
    lastTime->element = te;
  if(lastTimeElement != NULL)
    lastTimeElement->next = te;
  lastTimeElement = te;
}

#if __STDC__
void sgTimeElementEnd ()
#else
void sgTimeElementEnd ()
#endif
{
  time_switch = 0;
  date_switch = 0;
  if(lastTimeElement->fromdate !=0){
    if(lastTimeElement->todate == 0)
      lastTimeElement->todate = lastTimeElement->fromdate + 86399;
    else 
      lastTimeElement->todate = lastTimeElement->todate + 86399;
  }
  if(lastTimeElement->from == 0 && lastTimeElement->to == 0)
    lastTimeElement->to = 1439; /* set time to 23:59 */
}

#if __STDC__
void sgTimeElementAdd (char *element, char type) 
#else
void sgTimeElementAdd (element, type) 
     char *element;
     char type;
#endif
{
  struct TimeElement *te;
  char *p;
  char wday = 0;
  int h,m,Y,M = 0,D = -1;
  time_t sec;
  te = lastTimeElement;
  switch(type) {
  case T_WEEKDAY:
    p = strtok(element," \t,");
    do {
      if(*p == '*'){
	wday = 127;
      } else if(!strncmp(p,"sun",3)){
	wday = wday | 0x01;
      } else if(!strncmp(p,"mon",3)){
	wday = wday | 0x02;
      } else if(!strncmp(p,"tue",3)){
	wday = wday | 0x04;
      } else if(!strncmp(p,"wed",3)){
	wday = wday | 0x08;
      } else if(!strncmp(p,"thu",3)){
	wday = wday | 0x10;
      } else if(!strncmp(p,"fri",3)){
	wday = wday | 0x20;
      } else if(!strncmp(p,"sat",3)){
	wday = wday | 0x40;
      }
      p=strtok(NULL," \t,");
    } while(p != NULL);
    te->wday = wday;
    break;
  case T_TVAL:
    sscanf(element,"%d:%d",&h,&m);
    if((h < 0 && h > 24) && (m < 0 && m > 59))
      sgLogFatal("%s: FATAL: time formaterror in %s line %d",
		      progname, configFile,lineno);
    if(time_switch == 0){
      time_switch++;
      te->from = (h * 60) + m ;
    } else {
      time_switch=0;
      te->to = (h * 60) + m ;
    }
    break;
  case T_DVAL:
    sec = date2sec(element);
    if(sec == -1){
      sgLogFatal("%s: FATAL: date formaterror in %s line %d",
		      progname, configFile,lineno);
    }
    if(date_switch == 0){
      date_switch++;
      te->fromdate = sec;
    } else {
      date_switch=0;
      te->todate = sec;
    }
    break;
  case T_DVALCRON:
    p = strtok(element,"-.");
    Y = atoi(p);
    if(*p == '*')
      Y = -1;
    else
      Y = atoi(p);
    while((p=strtok(NULL,"-.")) != NULL){
      if(*p == '*')
	if(M == 0)
	  M = -1;
	else 
	  D = -1;
      else
	if(M == 0)
	  M = atoi(p);
	else
	  D = atoi(p);
    }
    te->y=Y; te->m=M; te->d=D;
    break;
  case T_WEEKLY:
    p = element;
    while(*p != '\0'){
      switch(*p){
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
			progname, configFile,lineno);
	break;
      }
      p++;
    }
    te->wday = wday;
    break;
  }
}


#if __STDC__
struct Time *sgTimeFindName(char *name)
#else
struct Time *sgTimeFindName(name)
     char *name;
#endif
{
  struct Time *p;
  for(p=Time; p != NULL; p = p->next){
    if(!strcmp(name,p->name))
      return p;
  }
  return NULL;
}

#if __STDC__
int sgTimeCmp(const int *a, const int *b)
#else
int sgTimeCmp(a, b)
     const int *a;
     const int *b;
#endif
{
  return *a - *b;
}

#if __STDC__
void sgTimeElementSortEvents()
#else
void sgTimeElementSortEvents()
#endif
{
 struct Time *p;
 struct TimeElement *te;
 int i = 0,j;
 int *t;
 if(Time != NULL){
   TimeElementsEvents = (int *) sgCalloc(numTimeElements * 2 , sizeof(int)); 
   t = (int *) sgCalloc(numTimeElements * 2, sizeof(int)); 
   for(p = Time; p != NULL; p = p->next){
     for(te = p->element; te != NULL; te = te->next){
       TimeElementsEvents[i++]= te->from == 0 ? 1440 : te->from;
       TimeElementsEvents[i++]= te->to == 0 ? 1440 : te->to;
     }
   }
   qsort(TimeElementsEvents,numTimeElements * 2,sizeof(int),
	 (void *) &sgTimeCmp);
   for(i=0,j=0; i < numTimeElements * 2; i++){
     if(j==0){
       t[j++] = TimeElementsEvents[i];
     } else {
       if(t[j-1] != TimeElementsEvents[i]){
	 t[j++]=TimeElementsEvents[i];
       }
     }
   }
   sgFree(TimeElementsEvents);
   numTimeElements = j;
   TimeElementsEvents = t;
 }
}

#if __STDC__
int sgTimeNextEvent()
#else
int sgTimeNextEvent()
#endif
{
  time_t t;
  struct tm *lt;
  int m = 0; 
  static int lastval= 0;
  static int index = 0;
#if HAVE_SIGACTION
  struct sigaction act;
#endif
  if(Time == NULL)
    return 0;
  t = time(NULL) + globalDebugTimeDelta;

  lt = localtime(&t); 
  m = (lt->tm_hour * 60) + lt->tm_min ;
  
  for(index=0; index < numTimeElements; index++){
    if(TimeElementsEvents[index] >= m){
      break;
    }
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
  if(lastval < m )
    m = (((1440 - m ) + lastval) * 60) - lt->tm_sec;
  else
    m = ((lastval - m) * 60) - lt->tm_sec;
  if(m <= 0)
    m = 30;
  sgLogError("INFO: recalculating alarm in %d seconds", (unsigned int)m); 
  alarm((unsigned int) m);
  sgTimeCheck(lt,t);
  sgTimeSetAcl();
  return 0;
}

#if __STDC__
int sgTimeCheck(struct tm *lt, time_t t)
#else
int sgTimeCheck(lt, t)
     struct tm *lt;
     time_t t;
#endif
{
  struct Time *sg;
  struct TimeElement *te;
  int min;
  if(Time == NULL)
    return -1;
  for(sg = Time; sg != NULL; sg = sg->next){
    sg->active = 0;
    for(te = sg->element; te != NULL ; te = te->next){
      if(te->wday != 0){
	if(((1 << lt->tm_wday ) & te->wday) != 0) {
	  min = (lt->tm_hour * 60 ) + lt->tm_min;
	  if(min >= te->from && min < te->to){
	    sg->active = 1;
	    break;
	  }
	}
      } else { /* date */
	if(te->fromdate != 0){
	  if(t >= te->fromdate && t <= te->todate){
	    min = (lt->tm_hour * 60 ) + lt->tm_min;
	    if(min >= te->from && min < te->to){
	      sg->active =1;
	      break;
	    }
	  }
	} else { /* cron */
	  if(te->y == -1 || te->y == (lt->tm_year + 1900)){
	    if(te->m == -1 || te->m == (lt->tm_mon + 1)){
	      if(te->d == -1 || te->d == (lt->tm_mday)){
		min = (lt->tm_hour * 60 ) + lt->tm_min;
		if(min >= te->from && min < te->to){
		  sg->active =1;
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
  for(acl=Acl; acl != NULL; acl = acl->next){
    if(acl->time != NULL){
      acl->active = acl->time->active;
      if(acl->within == OUTSIDE){
	if(acl->active){
	  acl->active = 0;
        }
	else {
	  acl->active = 1;
        }
      }
      if(acl->next != NULL && acl->next->within == ELSE){
	if(acl->active == 0){
	  acl->next->active = 1;
	} else {
	  acl->next->active = 0;
	}
      }
    }
  }
  for(d = Dest; d != NULL; d = d->next){
    if(d->time != NULL){
      d->active = d->time->active;
      if(d->within == OUTSIDE){
	if(d->active){
	  d->active = 0;
	} else {
	  d->active = 1;
        }
      }
    }
  }
  for(s = Source; s != NULL; s = s->next){
    if(s->time != NULL){
      s->active = s->time->active;
      if(s->within == OUTSIDE){
	if(s->active){
	  s->active = 0;
        }
	else  {
	  s->active = 1;
        }
      }
    }
  }
  for(rew = Rewrite; rew != NULL; rew = rew->next){
    if(rew->time != NULL){
      rew->active = rew->time->active;
      if(rew->within == OUTSIDE)
	if(rew->active)
	  rew->active = 0;
	else
	  rew->active = 1;
    }
  }
}

void sgTimeElementClone() {
  struct TimeElement *te = lastTimeElement, *tmp;
  if ( lastTimeElement == NULL ) {
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

void sgTimePrint() {
  struct Time *t;
  struct TimeElement *te;
  for(t = Time; t != NULL; t = t->next){
    printf("Time %s is ",t->name);
    t->active ? printf("active\n") : printf("inactive\n");
    for(te = t->element; te != NULL; te = te->next){
      printf("\tte->wday     = %x\n",te->wday);
      printf("\tte->from     = %d\n",te->from);
      printf("\tte->to       = %d\n",te->to);
      printf("\tte->y,m,d    = %d-%d-%d\n",te->y,te->m,te->d);
      printf("\tte->fromdate = %s\n",te->fromdate == 0 ?
             "0" : niso(te->fromdate));
      printf("\tte->todate   = %s\n\n",te->todate == 0 ?
             "0" : niso(te->todate));
    }
  }
}


/*
  Ip functions
*/


#if __STDC__
void sgSetIpType(int type, char *file, int line)
#else
void sgSetIpType(type, file, line)
     int type;
     char *file;
     int line;
#endif
{
  struct Ip *ip = sgIpLast(lastSource),*nip;
  char *p;
  char *f = file == NULL ? configFile : file;
  int l = line == 0 ? lineno : line ;
  unsigned long octet, *op = NULL;
  if(type == SG_IPTYPE_HOST)
    ip->mask = 0xffffffff;
  if(type == SG_IPTYPE_RANGE){
    if((op=sgConvDot(ip->str)) == NULL)
      sgLogFatal("%s: FATAL: address error in %s line %d", progname, f,l);
    else 
      ip->mask = *op;
    if(ip->net > ip->mask)
      sgLogFatal("%s: FATAL: iprange error in %s line %d", progname, f,l);
  }
  if(type == SG_IPTYPE_CLASS){
    p=ip->str;
    if(*p == '/')
      p++;
    if((op=sgConvDot(p)) == NULL)
      sgLogFatal("%s: FATAL: address error in %s line %d", progname, f,l);
    else 
      ip->mask = *op;
  }
  if(type == SG_IPTYPE_CIDR){
    p=ip->str;
    if(*p == '/')
      p++;
    octet = atoi(p);
    if(octet < 0 || octet > 32){
      sgLogFatal("%s: FATAL: prefix error /%s in %s line %d", progname,p, f,l);
    }
    if(octet == 32)
      ip->mask = 0xffffffff;
    else
      ip->mask = 0xffffffff ^ (0xffffffff >> octet);
    ip->net = ip->net & ip->mask;
  }
  ip->type = type;
  nip = (struct Ip *) sgCalloc(1,sizeof(struct Ip));
  ip->next = nip ;
}

#if __STDC__
void sgIp(char *name)
#else
void sgIp(name)
     char *name;
#endif
{
  struct Ip *ip;
  unsigned long *op;
  if(lastSource->ip == NULL){
    ip = (struct Ip *) sgCalloc(1,sizeof(struct Ip));
    ip->next = NULL;
    lastSource->ip = ip;
    lastSource->lastip = ip;
  } else {
    ip = sgIpLast(lastSource);
  }
  if(ip->net_is_set == 0){
    ip->net_is_set = 1;
    if((op=sgConvDot(name)) == NULL){
      sgLogFatal("%s: FATAL: address error in %s line %d", progname, configFile,lineno);
    } else 
      ip->net = *op;
  } else {
    ip->str = (char *) sgCalloc(1,strlen(name) + 1);
    strcpy(ip->str,name);
  }
}

#if __STDC__
struct Ip *sgIpLast(struct Source *s)
#else
struct Ip *sgIpLast(s)
     struct Source *s;
#endif
{
  struct Ip *ip,*ret = NULL ;
  for(ip=s->ip; ip != NULL; ip = ip->next)
    ret = ip;
  return ret;
}

/*
  ACL functions
*/


#if __STDC__
void sgAcl(char *name, char *value, int within)
#else
void sgAcl(name, value, within)
     char *name;
     char *value;
     int within;
#endif
{
  struct Acl *acl;
  struct Source *source = NULL;
  struct Time *time = NULL;
  int def = 0;
  char *s;
  if(name != NULL){
    /* due to some strange things in my yacc code */
    if((s=(char *) strchr(name,' ')) != NULL)
      *s='\0';    
    if((s=(char *) strchr(name,'\t')) != NULL)
      *s='\0';    
    /*
    if(Acl != NULL){
      if((struct Acl *) sgAclFindName(name) != NULL){
	sgLogFatal("%s: FATAL: ACL %s is defined in configfile %s",progname,name,configFile);
      }
    }
    */
  }
  if(lastAcl != NULL && name == NULL && within == ELSE) 
    name = lastAcl->name;
  acl = (struct Acl *)sgCalloc(1,sizeof(struct Acl));
  if(!strcmp(name,"default")){
    defaultAcl=acl;
    def++;
  } else {
    if((source = sgSourceFindName(name)) == NULL && !def){
      sgLogFatal("%s: FATAL: ACL source %s is not defined in configfile %s",
		      progname,name, configFile);
    }
  }
  acl->name = sgCalloc(1,strlen(name) + 1);
  strcpy(acl->name,name);
  acl->active = within == ELSE ? 0 : 1;
  acl->source = source;
  acl->pass = NULL;
  acl->rewriteDefault = 1;
  acl->rewrite = NULL;
  acl->redirect = NULL;
  acl->within = within;
  acl->logfile = NULL;
  acl->next = NULL;
  if(value != NULL){
    if((time = sgTimeFindName(value)) == NULL){
      sgLogFatal("%s: FATAL: ACL time %s is not defined in configfile %s",
		      progname,value, configFile);
    }
    acl->time = time;
  }
  if(Acl == NULL){
    Acl = acl;
    lastAcl = acl;
  } else {
    lastAcl->next = acl;
    lastAcl = acl;
  }
}

#if __STDC__
void sgAclSetValue (char *what, char *value, int allowed) 
#else
void sgAclSetValue (what, value, allowed)
     char *what;
     char *value;
     int allowed;
#endif
{
  char *subval = NULL;
  struct Destination *dest = NULL;
  struct sgRewrite *rewrite = NULL;
  struct AclDest *acldest;
  int type = ACL_TYPE_TERMINATOR;
  if(!strcmp(what,"pass")){
    if(!strcmp(value,"any") || !strcmp(value,"all"))
    {
      allowed = 1;
    }
    else if(!strcmp(value,"none"))
    {
      allowed=0;
    }
    else if(!strcmp(value,"in-addr")){
      type = ACL_TYPE_INADDR;
    } else if (!strncmp(value,"dnsbl",5)) {
      subval = strstr(value,":");
      type = ACL_TYPE_DNSBL;
    } else {
      if((dest = sgDestFindName(value)) == NULL){
	sgLogFatal("%s: FATAL: ACL destination %s is not defined in configfile %s",
			progname,value, configFile);
      } 
      type = ACL_TYPE_DEFAULT;
    }

    acldest = sgCalloc(1,sizeof(struct AclDest));
    acldest->name = (char *) sgCalloc(1,strlen(value) + 1);
    strcpy(acldest->name,value);
    acldest->dest = dest;
    acldest->access = allowed;
    acldest->type = type;
    if (type == ACL_TYPE_DNSBL)
    {
      if ((subval==NULL) || (subval[1])=='\0')//Config does not define which dns domain to use
      {
        acldest->dns_suffix = (char *) sgCalloc(1,strlen(".black.uribl.com")+1);
	strcpy(acldest->dns_suffix, ".black.uribl.com");
      } else {
        subval=subval+1;
	if (strspn(subval,".-abcdefghijklmnopqrstuvwxyz0123456789") != strlen(subval)  )
	  {
	   sgLogFatal("%s: FATAL: provided dnsbl \"%s\" doesn't look like a valid domain suffix",progname,subval);
          }
	acldest->dns_suffix = (char *) sgCalloc(1,strlen(subval)+1);
	strcpy(acldest->dns_suffix, ".");
	strcat(acldest->dns_suffix,subval);
      }
    }

    acldest->next = NULL;
    if(lastAcl->pass == NULL){
      lastAcl->pass = acldest;
    } else {
      lastAclDest->next = acldest;
    }
    lastAclDest = acldest;
  }

  if(!strcmp(what,"rewrite")){
    if(!strcmp(value,"none")){
      lastAcl->rewriteDefault = 0;
      lastAcl->rewrite = NULL;
    } else {
      if((rewrite = sgRewriteFindName(value)) == NULL){
	sgLogFatal("%s: FATAL: Rewrite %s is not defined in configfile %s",
			progname,value, configFile);
      }
      lastAcl->rewriteDefault = 0;
      lastAcl->rewrite = rewrite;
    }
  }
  if(!strcmp(what,"redirect")){
    if(strcmp(value,"default")){
      lastAcl->redirect = (char *) sgCalloc(1,strlen(value) + 1);
      strcpy(lastAcl->redirect,value);
    } else {
      lastAcl->redirect= NULL;
    }
  }
}

#if __STDC__
struct Acl *sgAclFindName(char *name)
#else
struct Acl *sgAclFindName(name)
     char *name;
#endif
{
  struct Acl *p;
  for(p=Acl; p != NULL; p = p->next){
    if(!strcmp(name,p->name))
      return p;
  }
  return NULL;
}


#if __STDC__
struct Acl *sgAclCheckSource(struct Source *source)
#else
struct Acl *sgAclCheckSource(source)
     struct Source *source;
#endif
{
  struct Acl *acl = defaultAcl;
  int found = 0;
  if(source != NULL){
    for(acl=Acl; acl != NULL; acl = acl->next){
      if(acl->source == source){
	if(acl->active){
	  found++;
	  break;
	} else {
	  if(acl->next->source == source && acl->next->active != 0){
	    found++;
	    acl=acl->next;
	    break;
	  }
	}
      }
    }
  }

  else {
      if( globalDebug == 1 ) { sgLogError("source not found"); }
       }

  if(!found) {
    acl = defaultAcl;

    if( globalDebug == 1 ) { sgLogError("no ACL matching source, using default"); }

  }
  return acl;
}

char *strip_fqdn(char *domain)
{
  char *result;
  result=strstr(domain,".");
  if (result == NULL)
    return NULL;
  return (result+1);
}

int is_blacklisted(char *domain, char *suffix)
{
  char target[MAX_BUF];
  struct addrinfo *res;
  int result;
  //Copying domain to target
  if (strlen(domain)+strlen(suffix)+1>MAX_BUF)
  {
    //Buffer overflow risk - just return and accept

    if( globalDebug == 1 ) { sgLogError("dnsbl : too long domain name - accepting without actual check"); }

     return(0);
   }
   strncpy(target,domain,strlen(domain)+1);
   strcat(target,suffix);

   result = getaddrinfo(target,NULL,NULL,&res);
   if (result == 0) //Result is defined
   {
     freeaddrinfo(res);
     return 1;
   }
   //If anything fails (DNS server not reachable, any problem in the resolution,
   //let's not block anything.
   return 0;
}

int blocked_by_dnsbl(char *domain, char *suffix)
{
  char *dn=domain;
  while ((dn !=NULL) && (strchr(dn,'.')!=NULL)) //No need to lookup "com.black.uribl.com"
  {
    if (is_blacklisted(dn,suffix))
      return(1);
    dn=strip_fqdn(dn);
  }
  return 0;
}


#if __STDC__
char *sgAclAccess(struct Source *src, struct Acl *acl, struct SquidInfo *req)
#else
char *sgAclAccess(src, acl, req)
     struct Source *src;
     struct Acl *acl;
     struct SquidInfo *req;
#endif
{
  int access = 1,result;
  char *redirect = NULL, *dbdata = NULL, *p;
  struct sgRewrite *rewrite = NULL;
  struct AclDest *aclpass = NULL;
  if(acl == NULL)
    return NULL;
  if(acl->pass == NULL)
    acl->pass = defaultAcl->pass;
  if(acl->pass != NULL){
    for(aclpass = acl->pass; aclpass != NULL; aclpass = aclpass->next){
      if(aclpass->dest != NULL && !aclpass->dest->active)
	continue;
      if(aclpass->type == ACL_TYPE_TERMINATOR){
	access=aclpass->access;
	break;
      }
      if(aclpass->type == ACL_TYPE_INADDR){
	if(req->dot){
	  access=aclpass->access;
	  break;
	}
	continue;
      }
      // http://www.yahoo.fr/ 172.16.2.32 - GET
      if(aclpass->type == ACL_TYPE_DNSBL){
        if (req->dot)
	  continue;
	if (blocked_by_dnsbl(req->domain, aclpass->dns_suffix)){
	  access=0;
	  break;
	}
	continue;
      }
      if(aclpass->dest->domainlistDb != NULL){
	result = defined(aclpass->dest->domainlistDb, req->domain, &dbdata);
       if(result != DB_NOTFOUND) {
         if(result){
           if(aclpass->access){
             access++;
             break; 
           } else {
             access = 0;
             break;
           }
	  }
	}
      else {
      }
      }
      if(aclpass->dest->urllistDb != NULL && access){
       result = defined(aclpass->dest->urllistDb,req->strippedurl, &dbdata);
       if (!result) {
         result = defined(aclpass->dest->urllistDb,req->furl, &dbdata);
       }
       if ((result) && (result != DB_NOTFOUND)) {
    if(aclpass->access){
      access++;
      break;
    } else {
      access = 0;
      break;
    }
  }
       else {
	}
      }
      if(aclpass->dest->regExp != NULL && access){
	if((result = sgRegExpMatch(aclpass->dest->regExp,req->furl)) != 0){
	  if(aclpass->access){
	    access++;
	    break;
	  } else {
	    access = 0;
	    break;
	  }
	}
      }
    }
    if(!access){
      if(dbdata != NULL)
	redirect = dbdata;
      else if(aclpass->dest != NULL && aclpass->dest->redirect != NULL)
	redirect = aclpass->dest->redirect;
      else if(aclpass->dest != NULL && aclpass->dest->rewrite != NULL &&
	      (redirect = 
	       sgRewriteExpression(aclpass->dest->rewrite,req->orig)) != NULL){
	;
      }
      else if(acl->redirect == NULL)
	redirect = defaultAcl->redirect;
      else
	redirect = acl->redirect;
    }
  } else {  /* acl->pass == NULL, probably defaultAcl->pass == NULL */
    access=0;
    redirect = defaultAcl->redirect;
  }
  if(acl->rewrite == NULL)
    rewrite = defaultAcl->rewrite;
  else
    rewrite = acl->rewrite;
  if(rewrite != NULL && access){
    if((p = sgRewriteExpression(rewrite,req->orig)) != NULL){
      redirect = p;
      if(rewrite->logfile != NULL){
	globalLogFile = rewrite->logfile;
       sgLogRequest(globalLogFile,req,acl,aclpass,rewrite,REQUEST_TYPE_REWRITE);
       return redirect;
      }
    }
  } else if(redirect != NULL) {
    redirect = sgParseRedirect(redirect, req, acl, aclpass);
  }
  if(src != NULL && src->logfile != NULL)
    globalLogFile = src->logfile;
  if(aclpass == NULL || aclpass->dest == NULL){
    if(defaultAcl->logfile != NULL)
     globalLogFile = defaultAcl->logfile;
  } else
    if(aclpass->dest->logfile != NULL)
      globalLogFile = aclpass->dest->logfile;
  if(globalLogFile != NULL) {
    if(redirect != NULL) {
      sgLogRequest(globalLogFile,req,acl,aclpass,NULL,REQUEST_TYPE_REDIRECT);
    } else {
      sgLogRequest(globalLogFile,req,acl,aclpass,NULL,REQUEST_TYPE_PASS);
    }
  }
  return redirect;
}

#if __STDC__
void yyerror(char *s)
#else
void yyerror(s)
     char *s;
#endif
{
  sgLogFatal("FATAL: %s in configfile %s line %d",s,configFile,lineno);
}


#if __STDC__
int yywrap()
#else
int yywrap()
#endif
{
  return 1;
}

/* returns 1 if user was found for the specified Source
 * returns a pointer to a UserInfo structure when found
 * handles all LDAP sub-lookups and caching
 */
#if __STDC__
int sgFindUser(struct Source *src, char *ident, struct UserInfo **rval)
#else
int sgFindUser(src, ident, rval)
       struct Source *src;
       char *ident;
       struct UserInfo **rval;
#endif

{
       int i, found;
       int CacheTimeOut;
       char *interval;
       struct UserInfo *userinfo;
       static struct UserInfo info;

  sgLogError("DEBUG: sgFindUser called with: %s", ident);  

       /* defined in the userDB? */
       if(defined(src->userDb, ident, (char **) &userinfo) == 1) {
#ifdef HAVE_LIBLDAP
       /* LDAP user? */
       if(!userinfo->ldapuser) {
          *rval = userinfo;
           return 1;       /* no, return regular user */
       }

       /* from here on, we assume it is an LDAP user */

       /* is this info valid? */
       interval = sgSettingGetValue("ldapcachetime");
       CacheTimeOut = atoi(interval != NULL ? interval : "0");
       if((time(NULL) - userinfo->cachetime) <= CacheTimeOut) {
          if(userinfo->found)
                *rval = userinfo;
          return userinfo->found; /* yes */
       }
#endif
       }
       else {
               userinfo = NULL;        /* no record defined, must add our own*/
       }

       found = 0;                      /* assume not found */

#ifdef HAVE_LIBLDAP
       /* loop through all LDAP URLs and do a search */
       for(i = 0; i < src->ldapuserurlcount; i++) {

               found = sgDoLdapSearch(src->ldapuserurls[i], ident);

               /* cache every search in the user database */
               /* this should be safe, since squid only sends real idents
                  that have been authenticated (?) */

               /* any record defined from above? */
               if(userinfo == NULL) {
                       /* no, must use our own memory */
                       userinfo = &info;
                       info.status = 0;
                       info.time = 0;
                       info.consumed = 0;
                       info.last = 0;
                       info.ldapuser = 1;
                       info.found = found;
                       info.cachetime = time(NULL);
               }
               else {
                       /* yes, just update the found flag */
                       userinfo->found = found;
                       userinfo->cachetime = time(NULL);
               }

               sgDbUpdate(src->userDb, ident, (char *) userinfo,
                       sizeof(struct UserInfo));
                sgLogError("Added LDAP source: %s", ident); 

               if(found) {
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
#if __STDC__
int sgFindIp(struct Source *src, char *net, struct IpInfo **rval)
#else
int sgFindIp(src, net, rval)
       struct Source *src;
       char *net;
       struct IpInfo **rval;
#endif

{
       int i, found;
       int CacheTimeOut;
       char *interval;
       struct IpInfo *ipinfo;
       static struct IpInfo info;
/* DEBUG
  sgLogError("debug : sgfindip called with: %s", net);
*/
       /* defined in the ipDB? */
       if(defined(src->ipDb, net, (char **) &ipinfo) == 1) {
               /* LDAP ip? */
               if(!ipinfo->ldapip) {
                       *rval = ipinfo;
                       return 1;       /* no, return regular ip */
               }

               /* from here on, we assume it is an LDAP ip */

               /* is this info valid? */
               interval = sgSettingGetValue("ldapcachetime");
               CacheTimeOut = atoi(interval != NULL ? interval : "0");
               if((time(NULL) - ipinfo->cachetime) <= CacheTimeOut) {
                       if(ipinfo->found)
                               *rval = ipinfo;
                       return ipinfo->found; /* yes */
               }
       }
       else {
               ipinfo = NULL;        /* no record defined, must add our own*/
       }

       found = 0;                      /* assume not found */

       /* loop through all LDAP URLs and do a search */
       for(i = 0; i < src->ldapipurlcount; i++) {

               found = sgDoLdapSearch(src->ldapipurls[i], net);

               /* cache every search in the ip database */
               /* this should be safe, since squid only sends real ip adresses (?) */
               /* any record defined from above? */
               if(ipinfo == NULL) {
                       /* no, must use our own memory */
                       ipinfo = &info;
                       info.status = 0;
                       info.time = 0;
                       info.consumed = 0;
                       info.last = 0;
                       info.ldapip = 1;
                       info.found = found;
                       info.cachetime = time(NULL);
               }
               else {
                       /* yes, just update the found flag */
                       ipinfo->found = found;
                       ipinfo->cachetime = time(NULL);
               }

               sgDbUpdate(src->ipDb, net, (char *) ipinfo,
                       sizeof(struct IpInfo));
               // DEBUG
               sgLogError("Added LDAP source: %s", net);

               if(found) {
                       *rval = ipinfo;
                       break;
               }
       }
       return found;
}

#if __STDC__
static int get_ldap_errno(LDAP *ld)
#else
static int get_ldap_errno(ld)
           LDAP *ld;
#endif

{
  int err = 0;
  if(ld) {
    if(ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err) != LDAP_OPT_SUCCESS)
        err = 0;
  }
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
               }
               else { 
                       *expand++ = *url++;
               }
       }

       if (expand < end) {
               *expand = '\0';         /* null terminate string */
               return 1;
       }
       else {
               return 0;
       }
}


/* does a raw LDAP search and returns 1 if found, 0 if not */
#if __STDC__
int sgDoLdapSearch(const char *url, const char *username)
#else
int sgDoLdapSearch(url, username)
       const char *url;
       const char *username;
#endif
{
       LDAPURLDesc *lud;
       LDAP *ld;
       LDAPMessage *ldapresult, *ldapentry;
       char *binddn = NULL, *bindpass = NULL;
       int ext_i;
       char **ldapvals;
       char buffer[MAX_BUF];
       int found = 0;
       int protoversion = -1;                  /* default to library defaults*/
       char *protosetting;

       /* Which protocol version should we use? */
       protosetting = sgSettingGetValue("ldapprotover");
       if (protosetting != NULL) {
               if (atoi(protosetting) == 3) {
                       protoversion = LDAP_VERSION3;
               }
               else if (atoi(protosetting) == 2) {
                       protoversion = LDAP_VERSION2;
               }
       }

       /* insert the username into the url, if needed... allow multiple %s */
       if (!expand_url(buffer, sizeof(buffer), url, username)) {
               sgLogError("%s: unable to expand LDAP URL: size: %u, username: "
                       "%s url: %s", progname, sizeof(buffer), username, url);
               return found;
       }

       /* Parse RFC2255 LDAP URL */
       if(ldap_url_parse(buffer, &lud)) {
               sgLogError("%s: can't parse LDAP url %s",progname, buffer);
               return found;
       }

       /* get a handle to an LDAP connection */
       if((ld = ldap_init(lud->lud_host, lud->lud_port)) == NULL) {
               sgLogError("%s: ldap_init(%s, %d) failed: %s", progname,
                       lud->lud_host, lud->lud_port, strerror(errno));
               ldap_free_urldesc(lud);
               return found;
       }

       /* force an LDAP protocol version if set */
       if (protoversion != -1) {
               if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
                       &protoversion) != LDAP_OPT_SUCCESS)
               {
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
       for(ext_i = 0;
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
               data++;             /* good extension, get data */

               /* do we recognize the key? */
               if (strncmp(key, "bindname=", 9) == 0)
               {
                       binddn = data;
                        sgLogError("Extracted binddn: %s", binddn); 
               }
               else if (strncmp(key, "x-bindpass=", 11) == 0)
               {
                       bindpass = data;
                        sgLogError("Extracted x-bindpass: %s", bindpass); 
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
       if(ldap_search_ext_s(ld, lud->lud_dn, lud->lud_scope, lud->lud_filter,
               lud->lud_attrs, 0, NULL, NULL, NULL, -1,
               &ldapresult) != LDAP_SUCCESS) {


               sgLogError("%s: ldap_search_ext_s failed: %s "

                       "(params: %s, %d, %s, %s)",
                       progname, ldap_err2string(get_ldap_errno(ld)),
                       lud->lud_dn, lud->lud_scope, lud->lud_filter,
                       lud->lud_attrs[0]);


               ldap_unbind(ld);
               ldap_free_urldesc(lud);
               return found;
       }

       /* return hash */
       ldapentry = ldap_first_entry(ld, ldapresult);
       if(ldapentry != NULL) {
               /* Use first attribute to get value */
               ldapvals = ldap_get_values(ld, ldapentry, lud->lud_attrs[0]);
               if(ldapvals != NULL) {
                       if(*ldapvals != NULL)
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

