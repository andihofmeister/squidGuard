#ifndef SG_DB_H
#define SG_DB_H 1

#include <sys/types.h>

#define SGDBTYPE_DOMAINLIST 1
#define SGDBTYPE_URLLIST 2
#define SGDBTYPE_USERLIST 3

struct sgDb;

struct sgDb *sgDbInit(int, char *);
void freeDb(struct sgDb *);

void sgDbLoadTextFile(struct sgDb *, char *, int);
int sgDbUpdate(struct sgDb *, const char *, void *, size_t);
int sgDbSearch(struct sgDb *, const char *, void **, size_t *);
int sgDbLookup(struct sgDb *, const char *, void **, size_t *);
int defined(struct sgDb *, const char *);

void setDBHome(const char *value);

#endif
