/*
 * By accepting this notice, you agree to be bound by the following
 * agreements:
 *
 * This software product, squidGuard, is copyrighted
 * (C) 2012, Andreas Hofmeister, Collax GmbH,
 * (C) 1998-2009 by Christine Kronberg, Shalla Secure Services.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License (version 2) as
 * published by the Free Software Foundation.  It is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License (GPL) for more details.
 *
 * You should have received a copy of the GNU General Public License
 * (GPL) along with this program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <memory.h>

#include "sgMemory.h"
#include "sgReadBuffer.h"

#define BUF_INCR 128
#define BUF_LOW  32

static volatile sig_atomic_t gotHup = 0;
static volatile sig_atomic_t gotExitSig = 0;

struct ReadBuffer {
	int	fd;
	char *	buffer;
	size_t	size;
	off_t	bnow;
};

struct ReadBuffer *newReadBuffer(int fd)
{
	struct ReadBuffer *result = sgMalloc(sizeof(struct ReadBuffer));

	result->fd = fd;
	result->buffer = sgMalloc(BUF_INCR);
	result->size = BUF_INCR;
	result->bnow = 0;

	return result;
}

void freeReadBuffer(struct ReadBuffer *buf)
{
	sgFree(buf->buffer);
	buf->buffer = NULL;
	buf->size = 0;
	buf->bnow = 0;
	buf->fd = -1;
}

static void extendReadBuffer(struct ReadBuffer *buf)
{
	buf->buffer = sgRealloc(buf->buffer, buf->size + BUF_INCR);
	buf->size += BUF_INCR;
}

static void hupSigHandler(int sig)
{
	gotHup = 1;
}

static void exitSigHandler(int sig)
{
	gotExitSig = 1;
}

sigset_t sigmask;
sigset_t empty_mask;

static int setupSigHandler(int signal, void (*handler)(int))
{
	struct  sigaction sa;

	sa.sa_flags = 0;
	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);

	if (sigaction(signal, &sa, NULL) == -1) {
		perror("sigaction");
		return 0;
	}

	return 1;
}

int setupSignals()
{
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGHUP);

	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
		perror("sigprocmask");
		return 0;
	}

	if (!setupSigHandler(SIGHUP, hupSigHandler))
		return 0;

	if (!setupSigHandler(SIGINT, exitSigHandler))
		return 0;

	if (!setupSigHandler(SIGTERM, exitSigHandler))
		return 0;

	sigemptyset(&empty_mask);

	return 1;
}

/*
 * Check the bytes from start to start+len for a newline.  When found, copy
 * line to user buffer, adjust read buffer and return 1
 */
static int finishPending(struct ReadBuffer *buf, char *start, size_t check, char **line, size_t *len)
{
	char *end = NULL;

	if ((end = memchr(start, '\n', check)) != NULL) {
		size_t needed = end - buf->buffer + 1;

		/* make the line buffer big enough. */
		if (!*line || *len < needed + 1)
			*line = sgRealloc(*line, needed + 1);

		/* ... and copy the line, then terminate with \0 */
		memcpy(*line, buf->buffer, needed);
		*(*line + needed) = 0;

		/*
		 * now adjust the buffer so that the char after the
		 * nl is at position 0 in the buffer
		 */
		memmove(buf->buffer, end + 1, buf->bnow - needed);
		buf->bnow = buf->bnow - needed;

		return 1;
	}

	return 0;
}

/*
 * Buffered read like 'getline()', but with save signal handling.
 *
 * Arguments:
 *
 *   'buf' is a ReadBuffer struct as returned by 'newReadBuffer()' above.
 *
 *   '*line' is NULL or points to a malloc'ed buffer of *len bytes size.
 *
 *   If '*line' is NULL, a new buffer big enough to hold the input is allocated
 *   and the size is stored at *len. If *line is not NULL but not big enough to
 *   store the recent input line, the buffer is re-alloated and the new size is
 *   stored at *len.
 *
 * Result:
 *
 *   > 0   : a line has been found.
 *   = 0   : no new line read but SIGHUP recieved.
 *   < 0   : the program should exit
 *     -1  : buffer already destroyed, fd closed, SIGTERM caught.
 *     -2  : error in system call, errno should be set.
 */
int doBufferRead(struct ReadBuffer *buf, char **line, size_t *len)
{
	fd_set rfds;
	int r;

	if (buf->buffer == NULL)
		return -1;

	if (finishPending(buf, buf->buffer, buf->bnow, line, len))
		return 1;

	for (;; ) {
		FD_ZERO(&rfds);
		FD_SET(buf->fd, &rfds);

		r = pselect(buf->fd + 1, &rfds, NULL, NULL, NULL, &empty_mask);

		if (r == -1 && errno != EINTR)
			return -2;

		if (gotExitSig) {
			gotExitSig = 0;
			return -1;
		}

		if (gotHup) {
			gotHup = 0;
			return 0;
		}

		if (r) {
			ssize_t bytes = 0;
			ssize_t remain = buf->size - buf->bnow;
			char *start = NULL;

			if (remain <= BUF_LOW) {
				extendReadBuffer(buf);
				remain = buf->size - buf->bnow;
			}
			start = buf->buffer + buf->bnow;

			if ((bytes = read(buf->fd, start, remain)) > 0) {
				buf->bnow += bytes;
				if (finishPending(buf, start, bytes, line, len))
					return 1;
			} else if (bytes == 0) {
				return -1;
			} else {
				return -2;
			}
		}
	}

	return 0;
}

