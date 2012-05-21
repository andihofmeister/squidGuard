#include <string.h>
#include <stdio.h>

#include "sg.h"
#include "sgSetting.h"
#include "sgMatch.h"
#include "sgMemory.h"
#include "sgDb.h"
#include "sgLog.h"

struct UrlListPrivate {
	char *		name;
	struct sgDb *	urllistDb;
};

static int ulMatch(void *priv, const struct SquidInfo *req)
{
	struct UrlListPrivate *data = (struct UrlListPrivate *)priv;
	int result = 0;

	result = sgDbSearch(data->urllistDb, req->surl, NULL, NULL);

	if (!result)
		result = sgDbSearch(data->urllistDb, req->furl, NULL, NULL);

	if (!result)
		result = sgDbSearch(data->urllistDb, req->domain, NULL, NULL);

	if (result) {
		sgLogDebug("url found in url list %s", data->name);
		return 1;
	} else {
		sgLogDebug("url not found in url list %s", data->name);
		return 0;
	}
}

static void ulFree(void *priv)
{
	struct UrlListPrivate *data = (struct UrlListPrivate *)priv;

	freeDb(data->urllistDb);
	sgFree(data->name);
	sgFree(priv);
}

struct DestMatch *newDestUrlListMatch(const char *name, const char *urllist)
{
	struct DestMatch *result;
	struct UrlListPrivate *priv;
	const char *dbhome = getSetting("dbhome");
	char *filename;

	if (dbhome == NULL)
		dbhome = DEFAULT_DBHOME;

	if (urllist == NULL) {
		size_t len = strlen("/dest/") + strlen(name) + strlen("/urllist") +
			     strlen(dbhome) + strlen("/") + 4;
		filename = sgMalloc(len);
		snprintf(filename, len, "%s/dest/%s/urllist", dbhome, name);
	} else {
		if (urllist[0] == '/') {
			filename = sgStrdup(urllist);
		} else {
			size_t len = strlen(dbhome) + strlen("/") + strlen(urllist) + 4;
			filename = sgMalloc(len);
			snprintf(filename, len, "%s/%s", dbhome, urllist);
		}
	}

	sgLogDebug("init urllist %s", filename);

	if ((priv = sgMalloc(sizeof(struct UrlListPrivate))) == NULL) {
		sgFree(filename);
		return NULL;
	}

	if ((priv->urllistDb = sgDbInit(SGDBTYPE_URLLIST, filename)) == NULL) {
		sgFree(filename);
		sgFree(priv);
		return NULL;
	}

	if ((result = sgNewDestMatch(ulMatch, ulFree)) == NULL) {
		freeDb(priv->urllistDb);
		sgFree(filename);
		ulFree(priv);
	}

	result->priv = priv;
	priv->name = filename;

	return result;
}
