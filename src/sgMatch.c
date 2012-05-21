#include <string.h>

#include "sgMemory.h"
#include "sgMatch.h"

struct SourceMatch *sgNewSourceMatch(int type, source_match_func match, free_func freef)
{
	struct SourceMatch *sm = sgMalloc(sizeof(struct SourceMatch));

	if (sm == NULL)
		return NULL;

	sm->type = type;
	sm->next = NULL;
	sm->match = match;
	sm->free = freef;

	return sm;
}

void freeSourceMatch(struct SourceMatch *sm)
{
	if (sm->free)
		sm->free(sm->priv);
	sgFree(sm);
}

struct DestMatch *sgNewDestMatch(dest_match_func match, free_func freef)
{
	struct DestMatch *dm = sgMalloc(sizeof(struct DestMatch));

	if (dm == NULL)
		return NULL;

	dm->next = NULL;
	dm->match = match;
	dm->free = freef;

	return dm;
}

void freeDestMatch(struct DestMatch *dm)
{
	if (dm->free)
		dm->free(dm->priv);
	sgFree(dm);
}
