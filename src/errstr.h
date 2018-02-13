/** @internal @file src/errstr.h
 * @brief Error string object.
 */
/* Copyright (C) 2018 Petr Tesarik <ptesarik@suse.cz>

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   libkdumpfile is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/** Maximum length of the static error message. */
#define ERRBUF	160

struct errstr {
	char *str;		/**< Error string. */
	char *dyn;		/**< Dynamically allocated error string. */
	char buf[ERRBUF];	/**< Fallback buffer for the error string. */
};

/** Free up all resources associated with the error string.
 * @param err  Error string object.
 */
static inline void
err_cleanup(struct errstr *err)
{
	if (err->dyn)
		free(err->dyn);
}

/** Clear the error string.
 * @param err  Error string object.
 */
static inline void
err_clear(struct errstr *err)
{
	err->str = NULL;
}

/** Get the current content of the error string.
 * @param err  Error string object.
 * @returns    NUL-terminated error string.
 */
static inline const char *
err_str(const struct errstr *err)
{
	return err->str;
}

/* This declaration may not be available by default. */
extern int vsnprintf(char *, size_t, const char *, va_list);

/** Add a formatted message to an error string using va_list.
 * @param err     Error string object.
 * @param msgfmt  printf-like message format.
 * @param ap      Arguments of the format.
 *
 * This function is equivalent to @ref err_add, except that a va_list
 * argument is used instead of a variable number of arguments.
 */
static inline void
err_vadd(struct errstr *err, const char *msgfmt, va_list ap)
{
	static const char failure[] = "(bad format string)";
	static const char delim[] = { ':', ' ' };

	va_list aq;
	char *msg, *newbuf;
	int msglen, dlen;
	size_t remain;

	/* Get length of formatted message. */
	va_copy(aq, ap);
	msglen = vsnprintf(NULL, 0, msgfmt, aq);
	va_end(aq);

	/* Cope with invalid format string.  */
	if (msglen < 0) {
		msgfmt = failure;
		msglen = sizeof(failure) - 1;
	}

	/* Calculate required and already allocated space. */
	msg = err->str;
	if (!msg || !*msg) {
		msg = err->buf + sizeof(err->buf) - 1;
		*msg = '\0';
		remain = sizeof(err->buf) - 1;
		dlen = 0;
	} else {
		remain = msg - err->buf;
		if (remain >= sizeof(err->buf))
			remain = msg - err->dyn;
		dlen = sizeof(delim);
	}

	msglen += dlen;
	if (remain < msglen) {
		size_t curlen = strlen(msg);
		newbuf = realloc(err->dyn, 1 + curlen + msglen + 1);
		if (newbuf) {
			if (err->dyn <= msg && msg <= err->dyn + 1)
				msg += newbuf - err->dyn;
			err->dyn = newbuf;
			memmove(newbuf + msglen + 1, msg, curlen + 1);
			vsnprintf(newbuf + 1, msglen + 1, msgfmt, ap);
			msg = newbuf + msglen + 1;
			remain = msglen;
		} else if (remain) {
			char lbuf[ERRBUF];
			vsnprintf(lbuf, sizeof lbuf, msgfmt, ap);
			if (msglen - dlen >= sizeof(lbuf)) {
				lbuf[sizeof(lbuf) - 2] = '>';
				msglen = sizeof(lbuf) - 1 + dlen;
			}
			memcpy(msg - remain, lbuf + msglen - remain, remain);
			msglen = remain;
			*(msg - remain) = '<';
			--remain;
		} else {
			msglen = 0;
			*msg = '<';
		}
	} else
		vsnprintf(msg - msglen, msglen + 1, msgfmt, ap);

	/* Add delimiter (or its part) if needed. */
	if (dlen) {
		if (remain > dlen)
			remain = dlen;
		memcpy(msg - remain, delim + sizeof(delim) - remain, remain);
	}

	err->str = msg - msglen;
}

/** Add a formatted message to an error string.
 * @param err     Error string object.
 * @param msgfmt  printf-like message format.
 */
static inline void
__attribute__ ((format (printf, 2, 3)))
err_add(struct errstr *err, const char *msgfmt, ...)
{
	va_list ap;

	va_start(ap, msgfmt);
	err_vadd(err, msgfmt, ap);
	va_end(ap);
}
