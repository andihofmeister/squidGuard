#ifndef SG_GROUP_H
#define SG_GROUP_H 1

#include "sgMatch.h"

struct SourceMatch *newGroupMatch(const char *group);

void setGroupCacheTTL(const char *value);

#endif
