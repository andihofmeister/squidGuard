
#include "sg.h"
#include "sgMemory.h"
#include <netdb.h>

extern int groupDebug;

#define dprintf(...)    if (groupDebug) sgLogError(__VA_ARGS__)
#define dputs(s)        if (groupDebug) sgLogError("%s", s)

extern char *krbRealm;
extern void unescape(char *s);
extern void stripRealm(char *name, char *realm);

struct node {
	struct node *	next;
	char *		name;
};

static char *sstrdup(const char *cp)
{
	char *np;

	np = sgMalloc(strlen(cp) + 1);
	strcpy(np, cp);

	return np;
}

static struct node *addgroup(struct node *list, char *name)
{
	struct node *new, *tmp = NULL;

	new = sgCalloc(1, sizeof(*new));
	new->name = sstrdup(name);

	if (list != NULL) {
		for (tmp = list; tmp->next != NULL; tmp = tmp->next) ;
		tmp->next = new;
	} else {
		list = new;
	}

	return list;
}

void sgSourceNetGroup(char *group)
{
	extern struct Source *lastSource;

	dprintf("NETGROUP: Adding netgroup %s to source %s", group, lastSource->name);

	lastSource->netgrouplist = addgroup(lastSource->netgrouplist, group);
}

int sgCheckNetGroup(void *grouplist, char *ident, char *source)
{
	struct node *tmp;

	unescape(ident);

	stripRealm(ident, krbRealm);

	dprintf("NETGROUP: Checking user %s in source %s", ident, source);

	for (tmp = grouplist; tmp != NULL; tmp = tmp->next) {
		if (innetgr(tmp->name, NULL, ident, NULL)) {
			dprintf("NETGROUP: matched user %s in source %s", ident, source);
			return 1;
		}
	}

	return 0;
}
