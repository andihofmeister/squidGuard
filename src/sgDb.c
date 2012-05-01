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

#include "sg.h"

#define DATABASE        NULL

extern int globalUpdate;
extern char *globalCreateDb;
extern char **globalArgv;
extern int globalQuiet;
extern int showBar;     /* from main.c */

#if __STDC__
void sgDbInit(struct sgDb *Db, char *file)
#else
void sgDbInit(Db, file)
     struct sgDb *Db;
     char *file;
#endif
{
  struct stat st, st2;
  char *dbfile = NULL;
  char *update = NULL;
  int createdb = 0, ret;
  u_int32_t flag = 0;
  if(file != NULL){
    if(globalCreateDb != NULL && (!strcmp(globalCreateDb,"all") || 
       !sgStrRncmp(file,globalCreateDb,strlen(globalCreateDb))))
      createdb = 1;
    dbfile = (char *) sgMalloc(strlen(file) + 5);
    strcpy(dbfile,file);
    strcat(dbfile,".db");
    if(stat(dbfile,&st) == 0){

      if(stat(file,&st2) == 0)
        if(st.st_mtime >= st2.st_mtime)
	  createdb = 0;

      if(!createdb){
	sgLogNotice("INFO: loading dbfile %s",dbfile);
      }
    } else {
      if(!createdb){
	sgFree(dbfile);
	dbfile = NULL;
      }
    }
  }
#if DB_VERSION_MAJOR == 2
  Db->dbenv= db_init(Db->dbhome);
  memset(&Db->dbinfo, 0, sizeof(Db->dbinfo));
  Db->dbinfo.db_pagesize = 1024;              /* Page size: 1K.  */
  if(Db->type == SGDBTYPE_DOMAINLIST)
    Db->dbinfo.bt_compare = domainCompare;
#else
  /*since we are not sharing the db's, we does not nedd dbenv */
  //ret = db_init(Db->dbhome, &Db->dbenv);
  //if(ret)
  //  sgLogFatal("FATAL: error db_init %s", strerror(ret)); 
  Db->entries = 1;
  Db->dbenv = NULL;
  if ((ret = db_create(&Db->dbp, Db->dbenv, 0)) != 0){
    sgLogFatal("FATAL: Error db_create: %s", strerror(ret));
  }
  /*please feel free to experiment with cacesize and pagesize */
  //Db->dbp->set_cachesize(Db->dbp, 0, 1024 * 1024,0);
  //Db->dbp->set_pagesize(Db->dbp, 1024);
  if(Db->type == SGDBTYPE_DOMAINLIST)
    Db->dbp->set_bt_compare(Db->dbp, (void *) domainCompare);
#endif
#if DB_VERSION_MAJOR == 2
  if(globalUpdate || createdb || stat(dbfile,&st)){
    flag = DB_CREATE;
    if(createdb)
      flag = flag | DB_TRUNCATE;
    if ((errno = 
	 db_open(dbfile,DB_BTREE, flag, 0664, Db->dbenv, &Db->dbinfo, &Db->dbp)) != 0) {
      sgLogFatal("FATAL: Error db_open: %s", strerror(errno));
    }
  } else {
    if ((errno = 
	 db_open(dbfile,DB_BTREE, DB_RDONLY, 0664, Db->dbenv, &Db->dbinfo, &Db->dbp)) != 0) {
      sgLogFatal("FATAL: Error db_open: %s", strerror(errno));
    }
  }
#endif
#if DB_VERSION_MAJOR == 3
  if(globalUpdate || createdb || (dbfile != NULL && stat(dbfile,&st))){
    flag = DB_CREATE;
    if(createdb)
      flag = flag | DB_TRUNCATE;
    if ((ret = 
	 Db->dbp->open(Db->dbp, dbfile, NULL, DB_BTREE, flag, 0664)) != 0) {
      (void) Db->dbp->close(Db->dbp, 0);
      sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
    }
  } else {
    if ((ret = 
	 Db->dbp->open(Db->dbp, dbfile, NULL, DB_BTREE, DB_CREATE, 0664)) != 0) {
      sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
    }
  }
#endif
#if DB_VERSION_MAJOR == 4
  if(globalUpdate || createdb || (dbfile != NULL && stat(dbfile,&st))){
    flag = DB_CREATE;
    if(createdb)
      flag = flag | DB_TRUNCATE;
    if ((ret =
         Db->dbp->open(Db->dbp, NULL, dbfile, NULL, DB_BTREE, flag, 0664)) != 0) {
      (void) Db->dbp->close(Db->dbp, 0);
      sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
    }
  } else {
    if ((ret =
         Db->dbp->open(Db->dbp, NULL, dbfile, NULL, DB_BTREE, DB_CREATE, 0664)) != 0) {
      sgLogFatal("FATAL: Error db_open: %s", strerror(ret));
    }
  }
#endif
  if(file != NULL){
    if(dbfile == NULL ){
      sgDbLoadTextFile(Db,file,0);
      if(Db->entries == 0){
	(void)Db->dbp->close(Db->dbp,0);
#if DB_VERSION_MAJOR == 2
	db_appexit(Db->dbenv);
	Db->dbenv = NULL;
#else
	//Db->dbenv->close(Db->dbenv, 0);
	Db->dbenv = NULL;
#endif
      }
    }
    if(dbfile != NULL && createdb){
      sgDbLoadTextFile(Db,file,0);
      if(Db->entries == 0){
	(void)Db->dbp->close(Db->dbp,0);
#if DB_VERSION_MAJOR == 2
	db_appexit(Db->dbenv);
	Db->dbenv = NULL;
#else
	//Db->dbenv->close(Db->dbenv, 0);
	Db->dbenv = NULL;
#endif
      } else {
	sgLogNotice("INFO: create new dbfile %s",dbfile);
	(void)Db->dbp->sync(Db->dbp,0);
      }
    }
    if(globalUpdate){
      if(dbfile == NULL){
        sgLogError("ERROR: update dbfile %s.db. file does not exists, use -C to create",file);
      } else {
        update = (char *) sgMalloc(strlen(file) + 6);
        strcpy(update,file);
        strcat(update,".diff");
        if(stat(update,&st) == 0){
       	  sgLogNotice("INFO: update dbfile %s",dbfile);
  	  sgDbLoadTextFile(Db,update,1);
        }
        (void)Db->dbp->sync(Db->dbp,0);
      }
    }
  }
  if(dbfile != NULL)
    sgFree(dbfile);
}

#if __STDC__
int defined(struct sgDb *Db, char *request, char **retval)
#else
int defined(Db, request, retval)
     struct sgDb *Db;
     char *request;
     char **retval;
#endif

  {
  int errno, result = 0 ;
  u_int32_t   dbmethod = DB_SET_RANGE;
  char *data1 = NULL;
  char *data2 = NULL;
  static char dbdata[MAX_BUF];
  char *req = request, r[MAX_BUF + 1];

#if DB_VERSION_MAJOR == 2
  if ((errno = Db->dbp->cursor(Db->dbp, NULL, &Db->dbcp,0)) != 0)
    {
    sgLogFatal("FATAL: cursor: %s", strerror(errno));
    exit (1);
    }
#else
  if ((errno = Db->dbp->cursor(Db->dbp, NULL, &Db->dbcp,0)) != 0)
    {
    sgLogFatal("FATAL: cursor: %s", strerror(errno));
    exit (1);
    }
#endif

  switch ( Db->type )
    {
    case SGDBTYPE_DOMAINLIST:
      r[0]='.'; r[1] = '\0';
      strcat(r,request);
      req=r;
      break;
    case SGDBTYPE_USERLIST:
      dbmethod = DB_SET;
      break;
    default:
      break;
    }

  memset(&Db->key, 0, sizeof(DBT));
  memset(&Db->data, 0, sizeof(DBT));
  Db->key.data = req;
  Db->key.size = strlen(req);
  errno= Db->dbcp->c_get(Db->dbcp, &Db->key, &Db->data, dbmethod);


  switch (errno )
    {
    case EAGAIN:                    /* Deadlock. */
      break;
    case 0:                         /* Success. */
      data1 =(char *)  sgCalloc(1,Db->key.size + 1);
      strncpy(data1, Db->key.data, Db->key.size);
      if (!strncmp(req,data1,Db->key.size))
        {
        result = 1;
        }
      else
        {
        switch (errno = Db->dbcp->c_get(Db->dbcp, &Db->key, &Db->data, DB_PREV))
          {
          case DB_NOTFOUND:
            errno = Db->dbcp->c_get(Db->dbcp, &Db->key, &Db->data, DB_FIRST);
            /* ONTOP */
            break;
          case 0:
            data2 =(char *)  sgCalloc(1,Db->key.size + 1);
            strncpy(data2, Db->key.data, Db->key.size);
            /* PPREV */
            if(Db->type == SGDBTYPE_DOMAINLIST)
              {
              if((sgStrRncmp(data1,data2,Db->key.size) != 0) && (!sgStrRncmp(data2,req,Db->key.size)))
                {
                result=1;
                }
              }
            else
              {
              if((strncmp(data1,data2,Db->key.size) != 0) && (!strncmp(data2,req,Db->key.size)))
                {
                result = 1;
                }
              }
            free(data2);
          }
        }
      free(data1);
      break;
    case DB_NOTFOUND:               /* Not found. */
      if (Db->type == SGDBTYPE_USERLIST)
        {
        result = 0;
        break;
        }
      switch (errno = Db->dbcp->c_get(Db->dbcp, &Db->key, &Db->data, DB_LAST))
        {
        case DB_NOTFOUND:
          result = DB_NOTFOUND;
          break;
        case 0:
          data1 =(char *)  sgCalloc(1,Db->key.size + 1);
          strncpy(data1, Db->key.data, Db->key.size);
          if(Db->type == SGDBTYPE_DOMAINLIST)
            {
            if(!sgStrRncmp(data1,req,Db->key.size))
              {
              result=1;
              }
            }
          else
            {
            if(!strncmp(data1,req,Db->key.size))
              {
              result = 1;
              }
            }
          free(data1);
          break;
        }
      break;
    }

  if(result == 1)
    if(retval != NULL && Db->data.size > 1){
      if(Db->data.size >= sizeof(dbdata))
        sgLogFatal("FATAL: Data size too large in defined()");
      memcpy(dbdata,Db->data.data,Db->data.size);
      *(dbdata + Db->data.size) = '\0';
      *retval = dbdata;
    } 
  memset(&Db->data, 0, sizeof(Db->data));
  (void)Db->dbcp->c_close(Db->dbcp);
  return result;
}

static int stdoutisatty;

#if __STDC__
void startProgressBar()
#else
void startProgressBar()
#endif
{
  stdoutisatty = isatty(STDOUT_FILENO);

  if(1 == stdoutisatty)
  {
    /* do nothing */
  }
  else
  {
    printf("    [");
    fflush(stderr);
  }
  return;
}

#if __STDC__
void finishProgressBar()
#else
void finishProgressBar()
#endif
{
  if(1 == stdoutisatty)
  {
    printf("\n");
  }
  else
  {
    printf("] 100 %% done\n");
  }
  fflush(stderr);
  return;
}

#if __STDC__
void updateProgressBar(float prog)
#else
void updateProgressBar(prog)
	float prog;
#endif
{
  if(1 == stdoutisatty)
  {
    int j,k=0;
    k = (int)(prog * 50.0);
    printf("\r");fflush(stderr);
    printf("    [");
    for(j=0; j<50; j++)
    {
      if(j <= k)
        printf("=");
      else
        printf(" ");
    }
    printf("] %d %% done", (int)(prog*100.0));fflush(stderr);
  }
  else
  {
    if(((int)(prog*100.0) % 100) == 0)
      printf(".");fflush(stderr);
  }

  return;
}

#if __STDC__
void sgDbLoadTextFile(struct sgDb *Db, char *filename, int update)
#else
void sgDbLoadTextFile(Db, filename, update)
     struct sgDb *Db;
     char *filename;
     int update;
#endif
{
  DB *dbp ;
  char *key,*val,*p,line[MAX_BUF];
  char *k, nkey[MAX_BUF + 1];
  FILE *fp;
  int entries = 0, added = 0, add = 0, deleted = 0;
  size_t fpsz;
  size_t lnsz = 0;
  struct stat fpst;
  
  dbp = Db->dbp;
  Db->entries = 0;
  if ((fp = fopen(filename, "r")) == NULL) {
    sgLogError("%s: %s", filename, strerror(errno));
    return;
  }
  else {
    if ( showBar == 1 ) {
    printf("Processing file and database %s\n", filename);
    }
  }

  fstat(fileno(fp), &fpst);
  fpsz = fpst.st_size;
  if ( showBar == 1 ) {
    startProgressBar();
  }
  
  memset(&Db->key, 0, sizeof(DBT));
  memset(&Db->data, 0, sizeof(DBT));
  while(fgets(line, sizeof(line), fp) != NULL){

    lnsz += strlen(line);
    if ( showBar == 1 ) {
    updateProgressBar((float)lnsz/(float)fpsz);
    }
    
    if(*line == '#')
      continue;
    p = strchr(line,'\n');
    if(p != NULL && p != line){
      if(*(p - 1) == '\r') /* removing ^M  */
	p--;
      *p = '\0';
    }
    key = line;
    if(*key == '+' || *key == '-'){
      if(*key == '+')
	add = 1;
      else 
	add = 0;
      key++;
    }
    key = strtok(key," \t\n");
    if(key == NULL)
      continue;
    else {
      val = strtok(NULL,"\n");
      if( val != NULL){
        /* remove extra space before the redirect url */
        while (*val != '\0' && isspace(*val))
          val++; 
        if (*val == '\0') /* there was nothing but some trailing space */
          val = NULL;
      }
    }
    for(p=key; *p != '\0'; p++) /* convert key to lowercase chars */
      *p = tolower(*p);
    if(Db->type == SGDBTYPE_DOMAINLIST){
      nkey[0]='.'; nkey[1] = '\0';
      strcat(nkey,key);
      k=nkey;
    } else if(Db->type == SGDBTYPE_URLLIST){
      if(*key != '.')
	k = sgStripUrl(key);
      else 
	k = key;
    } else 
      k = key;
    Db->key.data = k;
    Db->key.size = strlen(k);
    if(val == NULL){
      Db->data.data = "";
      Db->data.size = 1 ;
    } else {
      Db->data.data = val;
      Db->data.size = strlen(val) ;
    }
    if(update && !add){
      errno = dbp->del(dbp, NULL, &Db->key, 0);
      deleted++;
      entries--;
    } else {
      switch (errno=dbp->put(dbp, NULL, &Db->key, &Db->data, 0)) {
      case 0:
	added++;
	/*FALLTHROUGH*/
      case DB_KEYEXIST:
        entries++;
	break;
      default:
	sgLogFatal("FATAL: sgDbLoadTextFile: put: %s", strerror(errno));
	break;
      }
    } 
  }
  if(update){
    sgLogNotice("INFO: update: added %d entries, deleted %d entries",added,deleted);
  }
  if ( showBar == 1 ) {
    finishProgressBar();
  }
  Db->entries = entries;
  fclose(fp);
}


#if __STDC__
void sgDbUpdate(struct sgDb *Db, char *key, char *value, size_t len)
#else
void sgDbUpdate(Db, key, value, len)
     struct sgDb *Db;
     char *key;
     char *value;
     int len;
#endif
{
  DB *dbp ;
  u_int32_t flags = DB_NOOVERWRITE;
  char key_buf[MAX_BUF];
  char value_buf[MAX_BUF];
  dbp = Db->dbp;
  memset(&Db->key, 0, sizeof(DBT));
  memset(&Db->data, 0, sizeof(DBT));
  strcpy(key_buf,key);
  Db->key.data = key_buf;
  Db->key.size = strlen(key) ;
  if(value == NULL){
    Db->data.data = "default";
    Db->data.size = 8 ;
  } else {
    if(len > sizeof(value_buf))
      sgLogFatal("FATAL: Buffer too large in sgDbUpdate()");
    memcpy(value_buf,value, len);
    Db->data.data = value_buf;
    Db->data.size = len ;
    flags = 0;
  }
  switch (errno = dbp->put(dbp, NULL, &Db->key, &Db->data, flags)) {
  case 0:
    break;
  case DB_KEYEXIST:
    /*sgLogError("ERROR: %s: key already exists", key_buf);*/
    break;
  default:
    sgLogFatal("FATAL: sgDbUpdate: put: %s", strerror(errno));
    break;
  }
}

#if DB_VERSION_MAJOR == 2
#if __STDC__
DB_ENV *db_init(char *dbhome)
#else
DB_ENV *db_init(dbhome)
     char *dbhome;
#endif
{
  DB_ENV *dbenv;
  
  dbenv = (DB_ENV *) sgCalloc(1,sizeof(DB_ENV));
  dbenv->db_errfile = stderr;
  dbenv->db_errpfx = "sg";
  
  if ((errno = db_appinit(dbhome, NULL, dbenv, DB_CREATE)) != 0) {
    sgLogFatal("FATAL: db_appinit: %s", strerror(errno));
  }
  return (dbenv);
}
/* db version greater than 2 */
#else
#if __STDC__
int db_init(char *dbhome, DB_ENV **dbenvp)
#else
int db_init(dbhome, dbenvp)
     char *dbhome;
     DB_ENV **dbenvp;
#endif
{
  int ret;
  DB_ENV *dbenv;

  if((ret = db_env_create(&dbenv, 0)) != 0)
    return ret;
  //dbenv->set_errfile(dbenv, stderr);  
  
  if((ret = dbenv->open(dbenv, dbhome, DB_CREATE | DB_INIT_MPOOL, 0)) == 0) {
    *dbenvp = dbenv;
    return 0;
  }
  (void) dbenv->close(dbenv, 0);
  return ret;
}
#endif


/*
  domainCompare does a reverse compare of two strings
*/

#if DB_VERSION_MAJOR == 2
#if __STDC__
int domainCompare (const DBT *a, const DBT *b)
#else
int domainCompare (a, b)
     DBT *a;
     DBT *b;
#endif
{
  register const char *a1 , *b1;
  register char ac1 , bc1;
  a1=(char *) a->data + a->size - 1;
  b1=(char *) b->data + b->size - 1;
  while (*a1 == *b1){
    if(b1 == b->data || a1 == a->data)
        break;
    a1--; b1--;
  }
  ac1 = *a1 == '.' ? '\1' : *a1;
  bc1 = *b1 == '.' ? '\1' : *b1;
  if(a1 == a->data && b1 == b->data)
    return ac1 - bc1;
  if(a1 == a->data)
    return -1;
  if(b1 == b->data)
    return 1;
  return ac1 - bc1;
}
#else
#if __STDC__
int domainCompare (const DB *dbp, const DBT *a, const DBT *b)
#else
int domainCompare (dbp, a, b)
     DB  *dbp;
     DBT *a;
     DBT *b;
#endif
{
  register const char *a1 , *b1;
  register char ac1 , bc1;
  a1=(char *) a->data + a->size - 1;
  b1=(char *) b->data + b->size - 1;
  while (*a1 == *b1){
    if(b1 == b->data || a1 == a->data)
        break;
    a1--; b1--;
  }
  ac1 = *a1 == '.' ? '\1' : *a1;
  bc1 = *b1 == '.' ? '\1' : *b1;
  if(a1 == a->data && b1 == b->data)
    return ac1 - bc1;
  if(a1 == a->data)
    return -1;
  if(b1 == b->data)
    return 1;
  return ac1 - bc1;
}
#endif




