/*
 * ppc64.c
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

#define MAX_INSN_LEN	100

struct disas_state {
	unsigned long flags;
};

#define SRR0_SET	1
#define SRR1_SET	2

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

static void
print_address(bfd_vma addr, struct disassemble_info *info)
{
	struct disas_priv *priv = info->stream;
	size_t remain = priv->insn + sizeof(priv->insn) - priv->iptr;
	int len = snprintf(priv->iptr, remain,
			   "0x%llx", (unsigned long long) addr);
	if (len > 0)
		priv->iptr += len;
}

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

		/* ppc64 starts with a jump instruction, but it
		 * may be NOPped out at runtime */
		if (pc == 4 && strcmp(insn, "b") && strcmp(insn, "nop"))
			return 0;

		/* The next instruction should be a trap */
		if (pc == 8 && strcmp(insn, "trap"))
			return 0;

		/* MSR can be modiied only in supervisor mode */
		if (!strcmp(insn, "mtmsrd"))
			return 1;

		/* Alternatively, a good rfid will also serve */
		if (priv->state.flags & SRR0_SET &&
		    priv->state.flags & SRR1_SET &&
		    !strcmp(insn, "rfid"))
			return 1;

		if (!strcmp(insn, "mtsrr0"))
			priv->state.flags |= SRR0_SET;
		if (!strcmp(insn, "mtsrr1"))
			priv->state.flags |= SRR1_SET;
	} while (count > 0);

	return 0;
}

int
looks_like_kcode_ppc64(struct dump_desc *dd, uint64_t addr)
{
	struct disassemble_info info;
	struct disas_priv priv;

	/* check ppc64 startup code */
	if (read_page(dd, addr / dd->page_size))
		return -1;

	memset(&priv, 0, sizeof priv);
#ifdef DIS_ASM_STYLED_PRINTF
	init_disassemble_info(&info, &priv, disas_fn, disas_styled_fn);
#else
	init_disassemble_info(&info, &priv, disas_fn);
#endif
	info.print_address_func = print_address;
	info.memory_error_func = error_func;
	info.buffer        = dd->page;
	info.buffer_vma    = addr;
	info.buffer_length = dd->page_size;
	info.arch          = bfd_arch_powerpc;
	info.mach          = bfd_mach_ppc64;
	disassemble_init_for_target(&info);
	print_insn = disassembler(bfd_arch_powerpc,
				  dd->endian != KDUMP_LITTLE_ENDIAN,
				  bfd_mach_ppc64, NULL);
	if (!print_insn)
		return 0;
	return disas_at(dd, &info, 0);
}
