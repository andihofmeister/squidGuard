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

static int matchNone(void *priv, const struct SquidInfo *info)
{
	return 0;
}

static struct DestMatch *newNoDestMatch()
{
	return sgNewDestMatch(matchNone, NULL);
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

	if ((now = findDestList("none")) == NULL) {
		now = newDestList("none");
		addDestListMatch(now, newNoDestMatch());
	}

	if ((now = findDestList("in-addr")) == NULL) {
		now = newDestList("in-addr");
		addDestListMatch(now, newInAddrMatch());
	}
}
