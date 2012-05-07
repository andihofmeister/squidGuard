
#ifndef SG_LOG_H
#define SG_LOG_H 1

void sgLog(struct LogFileStat *, char *, ...);
void sgLogDebug(char *, ...);
void sgLogNotice(char *, ...);
void sgLogWarn(char *, ...);
void sgLogError(char *, ...);
void sgLogFatal(char *, ...);
void sgSetGlobalErrorLogFile();
void sgLogRequest(struct LogFile *, struct SquidInfo *, struct Acl *, struct AclDest *, struct sgRewrite *, int);

#endif
