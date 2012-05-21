#ifndef SG_REQUEST_H
#define SG_REQUEST_H 1

#define MAX_BUF 12288

struct SquidInfo {
	char	protocol[MAX_BUF];
	char	domain[MAX_BUF];
	int	isAddress;
	char	url[MAX_BUF];
	char	orig[MAX_BUF];
	char	surl[MAX_BUF];
	char	furl[MAX_BUF];
	int	port;
	char	src[MAX_BUF];
	char	srcDomain[MAX_BUF];
	char	ident[MAX_BUF];
	char	method[MAX_BUF];
};

void setReverseLookup(const char *value);
int parseAuthzLine(char *line, struct SquidInfo *s);
int parseLine(char *line, struct SquidInfo *s);

char *substRedirect(const struct SquidInfo *req, const char *redirect, const char *srcClass, const char *destClass);

#endif
