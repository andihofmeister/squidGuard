#ifndef SG_SOURCE_DOMAIN_H
#define SG_SOURCE_DOMAIN_H 1

struct SourceMatch *newSourceDomainMatch(void);
void addDomainToSourceDomainMatch(struct SourceMatch *match, const char *domain);


#endif
