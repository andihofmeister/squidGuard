#ifndef SG_STATIC_SOURCE_H
#define SG_STATIC_SOURCE_H 1

#include "sgSourceList.h"

void addUserToSource(struct SourceList *, const char *);
void addUserListToSource(struct SourceList *, const char *);
void addExecUserListToSource(struct SourceList *, const char *);

void addIpToSource(struct SourceList *list, const char *ip);
void addIpListToSource(struct SourceList *list, char *file);

#endif
