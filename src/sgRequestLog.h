#ifndef SG_REQUEST_LOG_H
#define SG_REQUEST_LOG_H 1

struct RequestLog;

struct RequestLog *newRequestLog(const char *fileName, int anonymous, int verbose);
struct RequestLog *findRequestLog(const char *name);
void freeAllRequestLogs(void);
void reopenAllRequestLogs(void);

enum AccessResults;
struct SquidInfo;

void doRequestLog(struct RequestLog *log, const struct SquidInfo *req, const char *srcClass, const char *dstClass, const char *rewrite, enum AccessResults result);

extern struct RequestLog *defaultRequestLog;
void setDefaultRequestLog(struct RequestLog *log);

#endif
