#ifndef SG_DNSBL_H
#define SG_DNSBL_H 1

#include "sgMatch.h"

struct DestMatch *newDNSBLMatch(const char *suffix);

#endif
