#ifndef SG_MATCH_H
#define SG_MATCH_H 1

#include "sgRequest.h"

typedef int (*source_match_func)(void *priv, const struct SquidInfo *info);
typedef int (*dest_match_func)(void *priv, const struct SquidInfo *info);
typedef void (*free_func)(void *priv);

#define SOURCE_NO_MATCH         0
#define SOURCE_USER_MATCH       1
#define SOURCE_IP_MATCH         2
#define SOURCE_DOMAIN_MATCH     4

struct SourceMatch {
	struct SourceMatch *	next;
	void *			priv;
	int			type;
	source_match_func	match;
	free_func		free;
};

struct DestMatch {
	struct DestMatch *	next;
	void *			priv;
	dest_match_func		match;
	free_func		free;
};

struct SourceMatch *sgNewSourceMatch(int, source_match_func, free_func);
struct DestMatch *sgNewDestMatch(dest_match_func, free_func);

void freeSourceMatch(struct SourceMatch *);
void freeDestMatch(struct DestMatch *);

#endif
