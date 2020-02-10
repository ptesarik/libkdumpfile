/** @internal @file src/internal.h
 * @brief Macros for internal declarations.
 */
/* Copyright (C) 2018 Petr Tesarik <ptesarik@suse.com>

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

#ifndef _INTERNAL_H
#define _INTERNAL_H 1

#define STRINGIFY(x)	#x
#define XSTRINGIFY(x)	STRINGIFY(x)
#define CONCATENATE(a, b)	a ## b
#define XCONCATENATE(a, b)	CONCATENATE(a, b)

/** Assembler name corresponding to a C identifier. */
#define ASM_NAME(sym) \
	XCONCATENATE(__USER_LABEL_PREFIX__, sym)

#define PRIV_NAME(sym)		_kdumpfile_priv_ ## sym

#define TAG_PUB_NAME(tag, sym)	tag ## _ ## sym
#define XTAG_PUB_NAME(tag, sym)	TAG_PUB_NAME(tag, sym)
#define PUB_NAME(sym)		XTAG_PUB_NAME(LIBNAME, sym)

/* Minimize chance of name clashes (in a static link) */
#ifndef ENABLE_DEBUG
#define INTERNAL_DECL(type, sym, param)	\
	type sym param			\
	__asm__(XSTRINGIFY(ASM_NAME(PRIV_NAME(sym))))
#else
#define INTERNAL_DECL(type, sym, param)	\
	type sym param
#endif

#ifndef ENABLE_DEBUG
#define INTERNAL_ALIAS(x)		PUB_NAME(x)
#define _DECLARE_ALIAS(s, a)		\
	extern typeof(s) (a) __asm__(XSTRINGIFY(ASM_NAME(s)))
#define _DEFINE_ALIAS(s, a)		_DECLARE_ALIAS(s, a)
#else
#define INTERNAL_ALIAS(x)		internal_ ## x
#define _DECLARE_ALIAS(s, a)		\
	extern typeof(s) (a)
#define _DEFINE_ALIAS(s, a)		\
	extern typeof(s) (a)		\
	__attribute__((alias(STRINGIFY(s))))
#endif

/** Internal alias declaration. */
#define DECLARE_ALIAS(x) _DECLARE_ALIAS(PUB_NAME(x), internal_ ## x)

/** Define an internal alias for a symbol. */
#define DEFINE_ALIAS(x) _DEFINE_ALIAS(PUB_NAME(x), internal_ ## x)

#endif	/* internal.h */
