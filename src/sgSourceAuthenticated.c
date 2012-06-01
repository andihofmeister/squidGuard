
#include <stddef.h>

#include "sgRequest.h"
#include "sgMatch.h"
#include "sgSourceAuthenticated.h"

static int doSourceAuthMatch(void *priv, const struct SquidInfo * req)
{
	if (req->ident && (req->ident[0] != 0))
		return 0;

	return 1;
}

struct SourceMatch *newSourceAuthenticatedMatch(void)
{
	struct SourceMatch *result;

	result = sgNewSourceMatch(SOURCE_USER_MATCH, doSourceAuthMatch, NULL);

	if (result == NULL)
		return NULL;

	return result;
}

