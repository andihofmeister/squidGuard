#ifndef SG_LDAP_H
#define SG_LDAP_H 1

#include "sgMatch.h"

struct SourceMatch *newLDAPIPMatch(const char *url);
struct SourceMatch *newLDAPUserMatch(const char *url);

#endif
