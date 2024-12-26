/*
 * s390.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"

#include <stdarg.h>
#include <string.h>

#include <dis-asm.h>

#include "kdumpid.h"

#define DEFAULT_ZIPL_OFFSET	0x08000
#define DEFAULT_LOAD_ADDR	0x10000

/* Minimum length of correctly decoded instructions */
#define MIN_STARTUP_SIZE	0x40

#define MAX_INSN_LEN	100

struct disas_state {
	unsigned long flags;
};

#define SAM64_SEEN	1

struct disas_priv {
	char *iptr;
	struct disas_state state;

	char insn[MAX_INSN_LEN];
};

static const char sep[] = ", \t\r\n";
#define wsep	(sep+1)

static disassembler_ftype print_insn;

static void
append_insn(void *data, const char *fmt, va_list va)
{
	struct disas_priv *priv = data;
	size_t remain;
	int len;

	remain = priv->insn + sizeof(priv->insn) - priv->iptr;
	len = vsnprintf(priv->iptr, remain, fmt, va);
	if (len > 0)
		priv->iptr += len;
}

static int
disas_fn(void *data, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	append_insn(data, fmt, va);
	va_end(va);

	return 0;
}

#ifdef DIS_ASM_STYLED_PRINTF

static int
disas_styled_fn(void *data, enum disassembler_style style,
		const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	append_insn(data, fmt, va);
	va_end(va);

	return 0;
}

#endif	/* DIS_ASM_STYLED_PRINTF */

static void error_func(int status, bfd_vma memaddr,
		       struct disassemble_info *dinfo)
{
	/* intentionally empty */
}

static int
disas_at(struct dump_desc *dd, struct disassemble_info *info, unsigned pc)
{
	struct disas_priv *priv = info->stream;
	char *toksave;
	char *insn;
	int count;

	do {
		priv->iptr = priv->insn;
		count = print_insn(info->buffer_vma + pc, info);
		if (count < 0)
			break;
		pc += count;

		insn = strtok_r(priv->insn, wsep, &toksave);

		/* s390 setup code always starts with a basr instruction */
		if (pc == 0 && strcmp(insn, "basr"))
			break;

		/* Recognize z/Architecture from ESA/390 */
		if (!strcmp(insn, "sam64"))
			priv->state.flags |= SAM64_SEEN;

		/* invalid instruction? */
		if (!strcmp(insn, ".long"))
			break;
	} while (count > 0);

	return (pc >= MIN_STARTUP_SIZE);
}

int
looks_like_kcode_s390(struct dump_desc *dd, uint64_t addr)
{
	struct disassemble_info info;
	struct disas_priv priv;
	int ret = 0;

	/* check zIPL signature */
	if (read_page(dd, (addr + DEFAULT_ZIPL_OFFSET) / dd->page_size))
		return -1;

	if (!memcmp(dd->page, "zIPL", 4))
		ret |= 1;

	/* check s390 startup code */
	if (read_page(dd, (addr + DEFAULT_LOAD_ADDR) / dd->page_size))
		return -1;

	memset(&priv, 0, sizeof priv);
#ifdef DIS_ASM_STYLED_PRINTF
	init_disassemble_info(&info, &priv, disas_fn, disas_styled_fn);
#else
	init_disassemble_info(&info, &priv, disas_fn);
#endif
	info.memory_error_func = error_func;
	info.buffer        = dd->page;
	info.buffer_vma    = addr + DEFAULT_LOAD_ADDR;
	info.buffer_length = dd->page_size;
	info.arch          = bfd_arch_s390;
	info.mach          = bfd_mach_s390_64;
	disassemble_init_for_target(&info);
	print_insn = disassembler(bfd_arch_s390, TRUE,
				  bfd_mach_s390_64, NULL);
	if (!print_insn)
		return 0;
	ret |= disas_at(dd, &info, 0);

	if (ret > 0 && priv.state.flags & SAM64_SEEN)
		dd->arch = "s390x";

	return ret;
}
