
#ifndef SG_MEMORY_H
#define SG_MEMORY_H

void *sgMalloc(size_t);
void *sgCalloc(size_t, size_t);
void *sgRealloc(void *, size_t);

void _sgFree(void *);
#define sgFree( x ) { _sgFree(x); (x) = NULL; }


void sgFreeAllLists(void);
void sgFreeDestination(struct Destination *);
void sgFreeSource(struct Source *);
void sgFreeIp(struct Ip *);
void sgFreeSetting(struct Setting *);
void sgFreeTime(struct Time *);
void sgFreeRewrite(struct sgRewrite *);
void sgFreeAcl(struct Acl *);
void sgFreeAclDest(struct AclDest *);
void sgFreeLogFileStat(struct LogFileStat *);

#endif
