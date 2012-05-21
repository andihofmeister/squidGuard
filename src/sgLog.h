#ifndef SG_LOG_H
#define SG_LOG_H 1

void sgLogDebug(char *, ...);
void sgLogInfo(char *, ...);
void sgLogNotice(char *, ...);
void sgLogWarn(char *, ...);
void sgLogError(char *, ...);
void sgLogFatal(char *, ...);
void sgSetGlobalErrorLogFile();

void setSyslogFlag(const char *value);
void setDebugFlag(const char *value);


/*
 * void sgLogRequest(struct LogFile *, struct SquidInfo *, struct Acl *, struct AclDest *, struct sgRewrite *, int);
 */

#endif
