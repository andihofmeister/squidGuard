#ifndef SG_REGEX_H
#define SG_REGEX_H

#include "sgMatch.h"

struct DestMatch *newDestExpressionListMatch(char *name, char *exprlist, char *chcase);

struct RegexList;

struct RegexList *newRewrite(const char *name);
struct RegexList *findRewrite(const char *name);

char *applyRewrite(struct RegexList *list, const char *url);

void addRewriteExpression(struct RegexList *list, const char *expr);
void freeAllRewrites(void);

#endif
