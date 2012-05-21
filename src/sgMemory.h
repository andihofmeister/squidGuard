#ifndef SG_MEMORY_H
#define SG_MEMORY_H

#include <sys/types.h>

void *sgMalloc(size_t);
void *sgCalloc(size_t, size_t);
void *sgRealloc(void *, size_t);
char *sgStrdup(const char *in);

void _sgFree(void *);
#define sgFree(x) { _sgFree(x); (x) = NULL; }

void sgFreeAllLists(void);

#endif
