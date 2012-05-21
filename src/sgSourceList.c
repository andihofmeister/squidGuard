#include <string.h>

#include "sgMatch.h"
#include "sgSourceList.h"
#include "sgTimeMatch.h"
#include "sgDb.h"
#include "sgMemory.h"
#include "sgLog.h"

static struct SourceList *firstSource = NULL;
static struct SourceList *lastSource = NULL;

struct UserInfo {
	char *	ident;
	int	found;
	time_t	validUntil;
};

struct IpInfo {
	char *	ident;          // should be struct in_addr ?
	int	found;
	time_t	validUntil;
};

static struct UserInfo *newUserInfo(const char *ident, time_t ttl)
{
	struct UserInfo *result = sgMalloc(sizeof(struct UserInfo));

	if (result == NULL)
		return NULL;

	result->ident = sgStrdup(ident);

	result->found = 0;

	if (result->ident == NULL) {
		sgFree(result);
		return NULL;
	}

	if (ttl > 0)
		result->validUntil = time(NULL) + ttl;
	else
		result->validUntil = 0;

	return result;
}

static void freeUserInfo(struct UserInfo *info)
{
	sgFree(info->ident);
	sgFree(info);
}

static int validUserInfo(struct UserInfo *info)
{
	if (info == NULL)
		return 0;
	if (info->validUntil == 0)
		return 1;
	if (info->validUntil >= time(NULL))
		return 1;

	return 0;
}

static struct IpInfo *newIpInfo(const char *ident, time_t ttl)
{
	struct IpInfo *result = sgMalloc(sizeof(struct IpInfo));

	if (result == NULL)
		return NULL;

	result->ident = sgStrdup(ident);

	result->found = 0;

	if (result->ident == NULL) {
		sgFree(result);
		return NULL;
	}

	if (ttl > 0)
		result->validUntil = time(NULL) + ttl;
	else
		result->validUntil = 0;

	return result;
}

static void freeIpInfo(struct IpInfo *info)
{
	sgFree(info->ident);
	sgFree(info);
}

static int validIpInfo(struct IpInfo *info)
{
	if (info == NULL)
		return 0;
	if (info->validUntil == 0)
		return 1;
	if (info->validUntil >= time(NULL))
		return 1;

	return 0;
}

struct SourceList *findSourceList(const char *name)
{
	struct SourceList *now;

	for (now = firstSource; now != NULL; now = now->next)
		if (strcmp(now->name, name) == 0)
			return now;

	return NULL;
}

struct SourceList *newSourceList(const char *name)
{
	struct SourceList *result = sgMalloc(sizeof(struct SourceList));

	if (result == NULL)
		return NULL;

	result->name = sgStrdup(name);

	result->negativeCacheTime = 60;
	result->positiveCacheTime = 60;

	result->staticUsers = 0;
	result->staticIps = 0;

	result->first = NULL;
	result->last = NULL;
	result->next = NULL;

	result->userCache = sgDbInit(SGDBTYPE_USERLIST, NULL);
	result->ipCache = new_patricia(32);
	result->ip6Cache = new_patricia(128);

	result->time = NULL;
	result->log = NULL;

	if (lastSource == NULL) {
		firstSource = result;
		lastSource = result;
	} else {
		lastSource->next = result;
		lastSource = result;
	}

	return result;
}

void freeSourceList(struct SourceList *list)
{
	struct SourceMatch *now = list->first;

	while (now != NULL) {
		struct SourceMatch *next = now->next;
		freeSourceMatch(now);
		now = next;
	}

	list->first = list->last = NULL;

	destroy_patricia(list->ipCache, freeIpInfo);
	list->ipCache = NULL;

	destroy_patricia(list->ip6Cache, freeIpInfo);
	list->ip6Cache = NULL;

	freeDb(list->userCache);
	list->userCache = NULL;

	sgFree(list->name);
	sgFree(list);
}

void freeAllSourceLists()
{
	struct SourceList *now = firstSource;

	while (now != NULL) {
		struct SourceList *next = now->next;
		freeSourceList(now);
		now = next;
	}
	firstSource = NULL;
	lastSource = NULL;
}

struct SourceList *lastSourceList(void)
{
	return lastSource;
}

void addSourceListMatch(struct SourceList *list, struct SourceMatch *source)
{
	if (source == NULL) {
		sgLogDebug("refuse to add NULL match");
		return;
	}

	if (list == NULL)
		list = lastSource;

	if (list->first == NULL) {
		list->first = source;
		list->last = source;
	} else {
		source->next = list->last;
		list->last = source;
	}
}

void addSourceListTime(struct SourceList *list, const char *tname, int invert)
{
	if ((list->time = findTimeMatch(tname)) == NULL)
		sgLogError("time match %s is not defined", tname);

	list->timeOutside = invert;
}


void addSourceListLog(struct SourceList *list, struct RequestLog *log)
{
	if (list->log) {
		sgLogError("source list %s already has a log", list->name);
		return;
	}

	list->log = log;
}


static struct UserInfo *userCacheLookup(struct SourceList *list, const char *ident)
{
	struct UserInfo *cachedUser = NULL;
	void *data = NULL;
	size_t datalen = 0;

	sgLogDebug("looking up user %s", ident);

	if (sgDbLookup(list->userCache, ident, &data, &datalen)) {
		sgLogDebug("user %s found, addr is %p, len is %d (should be %d)",
			   ident, data, datalen, sizeof(struct UserInfo));
		cachedUser = data;
		if (cachedUser && datalen == sizeof(struct UserInfo))
			return cachedUser;
	}

	return NULL;
}

static void userCacheAdd(struct SourceList *list, const char *ident, int found)
{
	struct UserInfo *cachedUser;

	sgLogDebug("adding user %s, found=%d", ident, found);

	cachedUser = newUserInfo(ident, found ? list->positiveCacheTime : list->negativeCacheTime);
	cachedUser->found = found;

	sgDbUpdate(list->userCache, ident, cachedUser, sizeof(struct UserInfo));

	sgLogDebug("added user %s, addr was %p", ident, cachedUser);

	freeUserInfo(cachedUser);

	return;
}

void addUserPermanently(struct SourceList *list, const char *ident)
{
	struct UserInfo *cachedUser;

	cachedUser = newUserInfo(ident, 0);
	cachedUser->found = 1;

	sgDbUpdate(list->userCache, ident, cachedUser, sizeof(struct UserInfo));

	freeUserInfo(cachedUser);

	list->staticUsers++;
}

static struct IpInfo *ipCacheLookup(struct SourceList *list, const char *ip)
{
	prefix_t *prefix;
	patricia_node_t *node;

	if ((prefix = ascii2prefix(0, ip)) == NULL) {
		sgLogError("invalid prefix %s", ip);
		return NULL;
	}

	sgLogDebug("searching IPv%d address %s", (prefix->family == AF_INET) ? 4 : 6, ip);

	if (prefix->family == AF_INET)
		node = patricia_search_best(list->ipCache, prefix);
	else
		node = patricia_search_best(list->ip6Cache, prefix);

	sgLogDebug("address %s %sfound", ip, node ? "" : "not ");
	sgLogDebug("  has %sdata attached", (node && node->data) ? "" : "no ");

	deref_prefix(prefix);

	if (node && node->data)
		return node->data;

	return NULL;
}

static struct IpInfo *ipCacheAdd(struct SourceList *list, const char *ip, int found)
{
	struct IpInfo *cachedIp;
	prefix_t *prefix;
	patricia_node_t *node;

	if ((prefix = ascii2prefix(0, ip)) == NULL) {
		sgLogError("invalid prefix %s", ip);
		return NULL;
	}

	sgLogDebug("adding IPv%d address %s, found=%d",
		   (prefix->family == AF_INET) ? 4 : 6, ip, found);

	cachedIp = newIpInfo(ip, found ? list->positiveCacheTime : list->negativeCacheTime);
	cachedIp->found = found;

	if (prefix->family == AF_INET)
		node = patricia_lookup(list->ipCache, prefix);
	else
		node = patricia_lookup(list->ip6Cache, prefix);

	deref_prefix(prefix);

	if (!node) {
		sgLogDebug("inserting %s into the ip cache failed", ip);
		freeIpInfo(cachedIp);
		return NULL;
	}

	if (node->data) {
		sgLogDebug("%s already in ip cache, replace it.", ip);
		freeIpInfo(node->data);
		node->data = cachedIp;
	} else {
		node->data = cachedIp;
	}

	return cachedIp;
}

void addIpPermanently(struct SourceList *list, const char *ip)
{
	struct IpInfo *cachedIp = ipCacheAdd(list, ip, 1);

	if (cachedIp == NULL)
		return;
	cachedIp->validUntil = 0;
	list->staticIps++;
}

/*
 */
int matchSourceList(struct SourceList *list, const struct SquidInfo *info)
{
	struct SourceMatch *now;
	struct UserInfo *cachedUser;
	struct IpInfo *cachedIp;
	int result;

	int foundIp = 0;
	int ipMatches = 0;

	int foundUser = 0;
	int userMatches = 0;

	if (list->time) {
		result = matchTime(list->time);
		if (list->timeOutside) {
			if (result) {
				sgLogDebug("source list outside time %s", list->time->name);
				return 0;
			}
		} else {
			if (!result) {
				sgLogDebug("source list not within time %s", list->time->name);
				return 0;
			}
		}
	}

	cachedUser = userCacheLookup(list, info->ident);

	if (!validUserInfo(cachedUser)) {
		for (now = list->first; now != NULL; now = now->next) {
			if ((now->type & SOURCE_USER_MATCH) == 0)
				continue;

			userMatches++;

			if (now->match(now->priv, info) > 0) {
				foundUser++;
				break;
			}
		}

		userCacheAdd(list, info->ident, foundUser);
	} else {
		foundUser = cachedUser->found;
		sgLogDebug("user cache hit for %s = %d, valid = %ld",
			   info->ident, foundUser, cachedUser->validUntil);
	}

	cachedIp = ipCacheLookup(list, info->src);

	if (!validIpInfo(cachedIp)) {
		for (now = list->first; now != NULL; now = now->next) {
			if ((now->type & (SOURCE_IP_MATCH | SOURCE_DOMAIN_MATCH)) == 0)
				continue;

			ipMatches++;

			if (now->match(now->priv, info) > 0) {
				foundIp++;
				break;
			}
		}

		if (!cachedIp)
			ipCacheAdd(list, info->src, foundIp);
	} else {
		foundIp = cachedIp->found;
		sgLogDebug("IP cache hit for %s = %d, valid = %ld", info->src, foundIp, cachedIp->validUntil);
	}

	result = 1;

	sgLogDebug("user match %s: matches %d static users %d",
		   (userMatches > 0 || list->staticUsers > 0) ? "required" : "not required",
		   userMatches, list->staticUsers);

	if ((userMatches > 0 || list->staticUsers > 0) && (!foundUser))
		result = 0;

	sgLogDebug("ip match %s: matches %d static ips %d",
		   (ipMatches > 0 || list->staticIps > 0) ? "required" : "not required",
		   ipMatches, list->staticIps);

	if ((ipMatches > 0 || list->staticIps > 0) && (!foundIp))
		result = 0;

	return result;
}
