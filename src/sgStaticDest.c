#include <string.h>

#include "sgMatch.h"
#include "sgDestList.h"
#include "sgStaticDest.h"

static int matchAny(void *priv, const struct SquidInfo *info)
{
	return 1;
}

static struct DestMatch *newAnyDestMatch()
{
	return sgNewDestMatch(matchAny, NULL);
}

static int matchInAddr(void *priv, const struct SquidInfo *info)
{
	return info->isAddress;
}

static struct DestMatch *newInAddrMatch()
{
	return sgNewDestMatch(matchInAddr, NULL);
}

void makeStaticDestLists()
{
	struct DestList *now = NULL;

	if ((now = findDestList("any")) == NULL) {
		now = newDestList("any");
		addDestListMatch(now, newAnyDestMatch());
	}

	if ((now = findDestList("all")) == NULL) {
		now = newDestList("all");
		addDestListMatch(now, newAnyDestMatch());
	}

	if ((now = findDestList("none")) == NULL) {
		/* there is a hack in sgAccessList.c for this */
		now = newDestList("none");
		addDestListMatch(now, newAnyDestMatch());
	}

	if ((now = findDestList("in-addr")) == NULL) {
		now = newDestList("in-addr");
		addDestListMatch(now, newInAddrMatch());
	}
}
