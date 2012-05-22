

#ifndef SG_READ_BUFFER_H
#define SG_READ_BUFFER_H

struct ReadBuffer;

int setupSignals(void);

struct ReadBuffer *newReadBuffer(int fd);
int doBufferRead(struct ReadBuffer *buf, char **line, size_t *len);
void freeReadBuffer(struct ReadBuffer *buf);

#endif

