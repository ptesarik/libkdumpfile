/** @internal @file src/kdumpfile/diskdump.c
 * @brief Routines to read SADUMP files.
 */
/* Copyright (C) 2022 Petr Tesarik <ptesarik@suse.com>

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

#define _GNU_SOURCE

#include "kdumpfile-priv.h"

#include <stdlib.h>
#include <string.h>

/* Structure of a Fujitsu SADUMP file.
 *
 * Disclaimer: To my best knowledge, Fujitsu has never published official
 * documentation of their SADUMP (stand-alone dump) format. The following
 * information is based on reading makedumpfile and crash code and observing
 * a few sample SADUMP files from a PRIMEQUEST 2000 system.
 *
 * There are three SADUMP formats:
 * - single partition format
 * - diskset format
 * - media backup format
 *
 * Only the beginning of the file is different:
 *
 * single-partition:
 * - struct sadump_part_header with set_disk_set == 0
 *
 * diskset:
 * - struct sadump_part_header with set_disk_set == 1
 * - struct sadump_disk_set_header
 *
 * media backup:
 * - struct sadump_media_header
 * - struct sadump_part_header
 */

/** Default block size. */
#define DEFAULT_BLOCK_SIZE 4096

/** Position of the LMA (Long Mode Active) bit in the IA32_EFER MSR. */
#define IA32_EFER_LMA	10

/** Standard EFI time specification. */
struct efi_time {
	uint16_t year;		/**< Full year (1900 - 9999). */
	uint8_t month;		/**< Month (1 - 12). */
	uint8_t day;		/**< Day of the month (1 - 31). */
	uint8_t hour;		/**< Hour (0 - 23). */
	uint8_t minute;		/**< Minute (0 - 59). */
	uint8_t second;		/**< Second (0 - 59). */
	uint8_t _pad1;		/**< Padding. */
	uint32_t nanosecond;	/**< Nanosecond (0 - 999,999,999). */
	int16_t timezone;	/**< Timezone (-1440 - 1440 or 2047). */
	uint8_t daylight;	/**< Daylight saving time. */
	uint8_t _pad2;		/**< Padding. */
} __attribute__((packed));

/** Standard EFI GUID.
 * 128 bits containing a unique identifier value.
 */
struct efi_guid {
	uint32_t data1;		/**< (big-endian) GUID part #1 */
	uint16_t data2;		/**< (big-endian) GUID part #2 */
	uint16_t data3;		/**< (big-endian) GUID part #3 */
	uint8_t  data4[8];	/**< (big-endian) GUID part #4 and #5 */
} __attribute__((packed));

#define SADUMP_PART_SIGNATURE0	0x75646173 /**< 'sadu' */
#define SADUMP_PART_SIGNATURE1	0x0000706d /**< 'mp\0\0' */

/** Single-partition or diskset format header. */
struct sadump_part_header {
	/** Must be { SADUMP_PART_SIGNATURE0, SADUMP_PART_SIGNATURE1 } */
	uint32_t signature[2];

	/** Is SADUMP enabled? Apparently always 1. */
	uint32_t enable;

	/** Seconds until reboot after saving dump. */
	uint32_t reboot;

	/** Memory image format. Maybe not implemented? */
	uint32_t compress;

	/** Can this dump device be recycled for another dump? */
	uint32_t recycle;

	/** Dump device label. Unused? */
	uint32_t label[16];

	/** System UUID. */
	struct efi_guid sadump_id;

	/** Disk set UUID or single-partition UUID. */
	struct efi_guid disk_set_id;

	/** Dump device UUID. */
	struct efi_guid vol_id;

	/** Wall-clock time of the dump. */
	struct efi_time time_stamp;

	/** ID of this disk in a disk set, or 0 for a single partition. */
	uint32_t set_disk_set;

	/** Padding to a multiple of 64 bits. */
	uint32_t _pad;

	/** Amount of data saved to this device (bytes). */
	uint64_t used_device;

	/** Magic number for verification. */
	uint32_t magicnum[];
} __attribute__((packed));

/** One volume in disk set header. */
struct sadump_volume_info {
	struct efi_guid id;	/** Volume UUID. */
	uint64_t vol_size;	/** Device size. */
	uint32_t status;	/** Device status. */
	uint32_t cache_size;	/** Cache size. */
} __attribute__((packed));

/** Disk set header. */
struct sadump_disk_set_header {
	/** Size of the disk set header in blocks. */
	uint32_t disk_set_header_size;

	/** Number of disks in this disk set. */
	uint32_t disk_num;

	/** Size of the whole disk set. */
	uint64_t disk_set_size;

	/** Information about each volume. */
	struct sadump_volume_info vol_info[];
} __attribute__((packed));

/** Dump signature. */
#define SADUMP_SIGNATURE "sadump\0\0"

/** Dump header. */
struct sadump_header {
	/** Must be SADUMP_SIGNATURE. */
	char signature[8];

	/** Dump header version. */
	uint32_t header_version;

	/* Padding to a multiple of 64 bits. */
	uint32_t _pad1;

	/** Wall-clock time of the dump. */
	struct efi_time timestamp;

	/** Status. Undocumented. */
	uint32_t status;

	/** Compression flags. Undocumented. */
	uint32_t compress;

	/** Size of a block in bytes. */
	uint32_t block_size;

	/** Size of host-dependent headers in blocks. */
	uint32_t extra_hdr_size;

	/** Size of arch-dependent headers in blocks. */
	uint32_t sub_hdr_size;

	/** Size of the memory bitmap in blocks. */
	uint32_t bitmap_blocks;

	/** Size of the dumped memory bitmap in blocks. */
	uint32_t dumpable_bitmap_blocks;

	/** Highest PFN number. */
	uint32_t max_mapnr;

	/** Size of RAM in blocks. */
	uint32_t total_ram_blocks;

	/** Total number of blocks in the dump device. */
	uint32_t device_blocks;

	/** Number of blocks written to the dump device. */
	uint32_t written_blocks;

	/** CPU that handles the dump. */
	uint32_t current_cpu;

	/** Total number of CPUs in the system. */
	uint32_t nr_cpus;

	/** Padding to a multiple of 64 bits. */
	uint32_t _pad2;

	/** 64-bit max_mapnr (header_version 1 and later). */
	uint64_t max_mapnr_64;

	/** 64-bit total_ram_blocks (header_version 1 and later). */
	uint64_t total_ram_blocks_64;

	/** 64-bit device_blocks (header_version 1 and later). */
	uint64_t device_blocks_64;

	/** 64-bit written_blocks (header_version 1 and later). */
	uint64_t written_blocks_64;
} __attribute__((packed));

struct sadump_apic_state {
	uint64_t apic_id;
	uint64_t ldr;
} __attribute__((packed));

/** SMRAM CPU state. */
struct sadump_smram_cpu_state {
	uint64_t _reserved1[58];
	uint32_t gdt_hi;
	uint32_t ldt_hi;
	uint32_t idt_hi;
	uint32_t _reserved2[3];
	uint64_t io_eip;
	uint64_t _reserved3[10];
	uint32_t cr4;
	uint32_t _reserved4[18];
	uint32_t gdt_lo, gdt_limit;
	uint32_t idt_lo, idt_limit;
	uint32_t ldt_lo, ldt_limit;
	uint32_t ldt_info;
	uint64_t _reserved5[6];
	uint64_t eptp;
	uint32_t eptp_setting;
	uint32_t _reserved6[5];
	uint32_t smbase;
	uint32_t smm_revision_id;
	uint16_t io_instruction_restart;
	uint16_t auto_halt_restart;
	uint32_t _reserved7[6];
	uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
	uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
	uint64_t io_mem_addr;
	uint32_t io_misc;
	uint32_t es, cs, ss, ds, fs, gs;
	uint32_t ldtr;
	uint32_t tr;
	uint64_t dr7, dr6;
	uint64_t rip;
	uint64_t ia32_efer;
	uint64_t rflags;
	uint64_t cr3, cr0;
} __attribute__((packed));

/* Media backup format header. */
struct sadump_media_header {
	/** System UUID. */
	struct efi_guid sadump_id;

	/** Disk set UUID. */
	struct efi_guid disk_set_id;

	/** Wall-clock time of the dump. */
	struct efi_time time_stamp;

	/** Sequential number of the media file. */
	uint8_t sequential_num;

	/** Termination cord (whatever that means). */
	uint8_t term_cord;

	/** Size of the original disk set header. */
	uint8_t disk_set_header_size;

	/** Number of used disks of the original dump device. */
	uint8_t disks_in_use;
} __attribute__((packed));

/** Extents of a disk in a disk set. */
struct sadump_disk_extents {
	/** Page data offset inside the file. */
	off_t data_pos;

	/** Length of page data (in bytes). */
	off_t data_len;

	/** File index in file cache. */
	unsigned fidx;
};

/** SADUMP format-specific data. */
struct sadump_priv {
	/** SADUMP block size. */
	size_t block_size;

	/** Number of split files in this dump. */
	unsigned num_files;

	/** Dumpable page mapping. */
	struct pfn_file_map pfm;

	/** Disk extents. Indexed by disk number. */
	struct sadump_disk_extents ext[];
};

/** Identification of a disk in a disk set. */
struct disk_id {
	/** Dump device UUID. */
	struct efi_guid vol_id;

	/** Have we seen this disk yet? */
	bool seen;
};

/** Information about the whole disk set. */
struct disk_set_info {
	/** System UUID. */
	struct efi_guid sadump_id;

	/** Disk set UUID. */
	struct efi_guid disk_set_id;

	/** Wall-clock time of the dump. */
	struct efi_time time_stamp;

	/** Dumped page bitmap offset in the first disk. */
	off_t bmp_pos;
};

static void sadump_cleanup(struct kdump_shared *shared);

static kdump_status
sadump_get_bits(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		kdump_addr_t first, kdump_addr_t last, unsigned char *bits)
{
	struct kdump_shared *shared = bmp->priv;
	struct sadump_priv *sp;

	rwlock_rdlock(&shared->lock);
	sp = shared->fmtdata;
	get_pfn_map_bits(&sp->pfm, 1, first, last, bits);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static kdump_status
sadump_find_set(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	struct sadump_priv *sp;
	kdump_status ret;

	rwlock_rdlock(&shared->lock);
	sp = shared->fmtdata;
	ret = find_mapped_pfn(&sp->pfm, 1, idx)
		? KDUMP_OK
		: status_err(err, KDUMP_ERR_NODATA, "No such bit found");
	rwlock_unlock(&shared->lock);
	return ret;
}

static kdump_status
sadump_find_clear(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		    kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	struct sadump_priv *sp;

	rwlock_rdlock(&shared->lock);
	sp = shared->fmtdata;
	*idx = find_unmapped_pfn(&sp->pfm, 1, *idx);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static void
sadump_bmp_cleanup(const kdump_bmp_t *bmp)
{
	struct kdump_shared *shared = bmp->priv;
	shared_decref(shared);
}

static const struct kdump_bmp_ops sadump_bmp_ops = {
	.get_bits = sadump_get_bits,
	.find_set = sadump_find_set,
	.find_clear = sadump_find_clear,
	.cleanup = sadump_bmp_cleanup,
};

/** Read SADUMP dumped page bitmap.
 * @param ctx       Dump file object.
 * @param pfm       PFN-to-file map, updated on success.
 * @param fidx      Dump file index.
 * @param bmp_pos   Byte offset of the page bitmap inside the dump file.
 * @param bmp_len   Page bitmap length (in bytes).
 */
static kdump_status
read_bitmap(kdump_ctx_t *ctx, struct pfn_file_map *pfm,
	    unsigned fidx, off_t bmp_pos, size_t bmp_len)
{
	kdump_pfn_t max_bmp_pfn;
	struct fcache_chunk fch;
	kdump_status ret;

	max_bmp_pfn = (kdump_pfn_t)bmp_len * 8;
	if (get_max_pfn(ctx) > max_bmp_pfn)
		set_max_pfn(ctx, max_bmp_pfn);

	ret = fcache_get_chunk(ctx->shared->fcache, &fch,
			       bmp_len, fidx, bmp_pos);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read %zu bytes of page bitmap"
				 " at %llu",
				 bmp_len, (unsigned long long) bmp_pos);

	pfm->start_pfn = 0;
	pfm->end_pfn = max_bmp_pfn;
	ret = pfn_regions_from_bitmap(&ctx->err, pfm, fch.data, true,
				      pfm->start_pfn, max_bmp_pfn,
				      0, get_page_size(ctx));
	fcache_put_chunk(&fch);
	return ret;
}

static kdump_status
sadump_read_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	struct sadump_priv *sp = ctx->shared->fmtdata;
	kdump_pfn_t pfn = pio->addr.addr >> get_page_shift(ctx);
	const struct pfn_region *rgn;
	unsigned disknum;
	off_t pos;
	kdump_status ret;

	if (pfn >= get_max_pfn(ctx))
		return set_error(ctx, KDUMP_ERR_NODATA, "Out-of-bounds PFN");

	if (!(rgn = find_pfn_region(&sp->pfm, pfn)) ||
	    pfn < rgn->pfn) {
		if (get_zero_excluded(ctx)) {
			memset(pio->chunk.data, 0, get_page_size(ctx));
			return KDUMP_OK;
		}
		return set_error(ctx, KDUMP_ERR_NODATA, "Excluded page");
	}

	disknum = 0;
	pos = rgn->pos;
	while (pos >= sp->ext[disknum].data_len) {
		pos -= sp->ext[disknum].data_len;
		if (++disknum >= sp->num_files)
			return set_error(ctx, KDUMP_ERR_NODATA,
					 "Out-of-bounds PFN");
	}
	pos += sp->ext[disknum].data_pos;

	mutex_lock(&ctx->shared->cache_lock);
	ret = fcache_pread(ctx->shared->fcache, pio->chunk.data,
			   get_page_size(ctx), sp->ext[disknum].fidx, pos);
	mutex_unlock(&ctx->shared->cache_lock);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read page data at %llu",
				 (unsigned long long) rgn->pos);

	return KDUMP_OK;
}

static kdump_status
sadump_get_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	return cache_get_page(ctx, pio, sadump_read_page);
}

/* Initialize data structures for SADUMP.
 * @param ctx   Dump file object.
 * @returns     Error status.
 */
static kdump_status
init_sadump(kdump_ctx_t *ctx)
{
	struct sadump_priv *sp;

	sp = calloc(1, (sizeof *sp + get_num_files(ctx) * sizeof(sp->ext[0])));
	if (!sp)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate SADUMP private data");
	ctx->shared->fmtdata = sp;

	sp->num_files = get_num_files(ctx);

	if (!isset_byte_order(ctx))
		set_byte_order(ctx, KDUMP_LITTLE_ENDIAN);
	else if (get_byte_order(ctx) != KDUMP_LITTLE_ENDIAN)
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Only little endian SADUMP is implemented");

	set_addrspace_caps(ctx->xlat, ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR));
	return KDUMP_OK;
}

kdump_status
verify_magic_number(kdump_ctx_t *ctx, unsigned fidx, off_t *pos)
{
	struct fcache_entry fce;
	uint32_t magic, prevmagic;
	off_t magicpos, block_size;
	kdump_status status;

	magicpos = *pos + sizeof(struct sadump_part_header);
	status = fcache_get(ctx->shared->fcache, &fce, fidx, magicpos);
	if (status != KDUMP_OK)
		goto read_err;
	if (fce.len < sizeof(uint32_t))
		goto read_err_put;
	prevmagic = dump32toh(ctx, *(uint32_t*)fce.data);

	for (;;) {
		fce.data += sizeof(uint32_t);
		fce.len -= sizeof(uint32_t);
		magicpos += sizeof(uint32_t);
		if (!fce.len) {
			fcache_put(&fce);
			status = fcache_get(ctx->shared->fcache, &fce,
					    fidx, magicpos);
			if (status != KDUMP_OK)
				goto read_err;
			if (fce.len < sizeof(uint32_t))
				goto read_err_put;
		}
		magic = dump32toh(ctx, *(uint32_t*)fce.data);
                if (magic != 11 * (prevmagic + 7))
			break;
		prevmagic = magic;
	}
	fcache_put(&fce);
	block_size = magicpos - *pos;

	/* Check that it is a power of 2. */
        if (block_size != (block_size & ~(block_size - 1)))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid magic number at %llu",
				 (unsigned long long) magicpos);

	*pos = magicpos;
	return KDUMP_OK;

 read_err_put:
	fcache_put(&fce);
 read_err:
	return set_error(ctx, status,
			 "Cannot read magic number at %llu",
			 (unsigned long long) *pos);
}

/** Check whether media header matches partition header.
 * @param ctx   Dump file object.
 * @param smh   SADUMP media header.
 * @param sph   SADUMP partition header.
 * @returns     Error status.
 */
static kdump_status
check_media_part(kdump_ctx_t *ctx, const struct sadump_media_header *smh,
		 const struct sadump_part_header *sph)
{
	static const char errmsg[] =
		"Partition %s does not match media backup header";

	if (memcmp(&smh->sadump_id, &sph->sadump_id,
		   sizeof(struct efi_guid)))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 errmsg, "system ID");
	if (memcmp(&smh->disk_set_id, &sph->disk_set_id,
		   sizeof(struct efi_guid)))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 errmsg, "disk set ID");
	if (memcmp(&smh->time_stamp, &sph->time_stamp,
		   sizeof(struct efi_time)))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 errmsg, "timestamp");
	return KDUMP_OK;
}

/** Check whether two volume UUIDs match.
 * @param ctx   Dump file object.
 * @param ref   Reference UUID.
 * @param dmap  Disk identification (indexed by disk number).
 * @param num   Disk number.
 * @returns     Error status.
 */
static kdump_status
check_vol_id(kdump_ctx_t *ctx, const struct efi_guid *ref,
	     const struct disk_id *dmap, uint32_t num)
{
	return memcmp(ref, &dmap[num - 1].vol_id, sizeof(struct efi_guid))
		? set_error(ctx, KDUMP_ERR_CORRUPT,
			    "Disk #%" PRIu32 " volume ID mismatch", num)
		: KDUMP_OK;
}

/** Process the volume UUID of a disk.
 * @param ctx   Dump file object.
 * @param sph   SADUMP partition header.
 * @param dmap  Disk identification (indexed by disk number).
 * @param num   Disk number.
 * @returns     Error status.
 *
 * If the disk set has been initialized, check that the volume ID from
 * the partition header matches the volume ID from the volume info array.
 * If the disk set has not been initialized yet, store the volume ID,
 * so it can be checked when the volume info array is read.
 */
static kdump_status
process_vol_id(kdump_ctx_t *ctx, const struct sadump_part_header *sph,
	       struct disk_id *dmap, uint32_t num)
{
	if (dmap->seen)
		return check_vol_id(ctx, &sph->vol_id, dmap, num);

	memcpy(&dmap[num - 1].vol_id, &sph->vol_id, sizeof(struct efi_guid));
	return KDUMP_OK;
}

/** Initialize disk set information.
 * @param ctx   Dump file object.
 * @param fidx  File index in file cache.
 * @param pos   Position of the header in the file. Updated on success.
 * @param dmap  Disk identification (indexed by disk number).
 *              Updated on success.
 * @returns     Error status.
 */
kdump_status
init_disk_set(kdump_ctx_t *ctx, unsigned fidx, off_t *pos,
	      struct disk_id *dmap)
{
	struct sadump_priv *sp = ctx->shared->fmtdata;
	const struct sadump_disk_set_header *sdsh;
	struct fcache_chunk fch;
	uint32_t hdr_blocks, disk_num;
	size_t req_size, act_size;
	kdump_status status;
	uint32_t i;

	status = fcache_get_chunk(ctx->shared->fcache, &fch,
				  sizeof(uint32_t), fidx, *pos);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot read disk set header size at %llu",
				 (unsigned long long) *pos);
	hdr_blocks = dump32toh(ctx, *(uint32_t*)fch.data);
	fcache_put_chunk(&fch);

	status = fcache_get_chunk(ctx->shared->fcache, &fch,
				  hdr_blocks * sp->block_size, fidx, *pos);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot read disk set header (%"PRIu32" blocks) at %llu",
				 hdr_blocks, (unsigned long long) *pos);
	sdsh = fch.data;
	disk_num = dump32toh(ctx, sdsh->disk_num);
	if (disk_num != get_num_files(ctx)) {
		status = set_error(ctx, KDUMP_ERR_INVALID,
				   "Disk set comprises %"PRIu32" disk(s), but %u file(s) given",
				   disk_num, get_num_files(ctx));
		goto out;
	}

	req_size = sizeof sdsh + disk_num * sizeof sdsh->vol_info[0];
	act_size = hdr_blocks * sp->block_size;
	if (req_size > act_size) {
		status = set_error(ctx, KDUMP_ERR_CORRUPT,
				   "Disk set header too short (need %zu, have %zu)",
				   req_size, act_size);
		goto out;
	}

	for (i = 0; i < disk_num; ++i) {
		const struct efi_guid *sdsh_id = &sdsh->vol_info[i].id;
		if (dmap[i].seen) {
			status = check_vol_id(ctx, sdsh_id, dmap, i + 1);
			if (status != KDUMP_OK)
				goto out;
		} else
			memcpy(&dmap[i].vol_id, sdsh_id,
			       sizeof(struct efi_guid));
	}

	*pos += act_size;

 out:
	fcache_put_chunk(&fch);
	return status;
}

/** Open a SADUMP file.
 * @param ctx   Dump file object.
 * @param fidx  File index in file cache.
 * @param pos   Position of the SADUMP arch-dependent header within the file.
 * @param len   Length of the arch-dependent header.
 * @param cpus  Number of CPUs in the system.
 * @returns     Error status.
 */
static kdump_status
setup_arch(kdump_ctx_t *ctx, unsigned fidx, off_t pos, off_t len,
	   uint32_t cpus)
{
	struct sadump_smram_cpu_state cpu_state;
	uint32_t sz;
	uint_fast32_t i;
	kdump_status status;

	if (isset_arch_name(ctx)) {
		if (strcmp(get_arch_name(ctx), KDUMP_ARCH_X86_64) &&
		    strcmp(get_arch_name(ctx), KDUMP_ARCH_IA32))
			return set_error(ctx, KDUMP_ERR_NOTIMPL,
					 "Unsupported SADUMP architecture: %s",
					 get_arch_name(ctx));
		return KDUMP_OK;
	}

	status = fcache_pread(ctx->shared->fcache, &sz, sizeof sz, fidx, pos);
	sz /= cpus;
	if (sz < sizeof(struct sadump_smram_cpu_state))
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "CPU state too small: %" PRIu32, sz);

	pos += sizeof sz;
	pos += cpus * sizeof(struct sadump_apic_state);

	for (i = 0; i < cpus; ++i) {
		uint_fast64_t ia32_efer;
		status = fcache_pread(ctx->shared->fcache,
				      &cpu_state, sizeof cpu_state, fidx, pos);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot read CPU #%" PRIuFAST32 " state",
					 i);
		ia32_efer = dump64toh(ctx, cpu_state.ia32_efer);
		if (ia32_efer & ((uint64_t)1 << IA32_EFER_LMA)) {
			set_arch_name(ctx, KDUMP_ARCH_X86_64);
			return KDUMP_OK;
		}
		pos += sz;
	}

	set_arch_name(ctx, KDUMP_ARCH_IA32);
	return KDUMP_OK;
}

/** Open a SADUMP file.
 * @param ctx   Dump file object.
 * @param fidx  File index in file cache.
 * @param dsi   Disk set info. Updated on success.
 * @param dmap  Disk identification (indexed by disk number).
 *              Updated on success.
 * @param smh   SADUMP media header,
 *              or @c NULL if this is not a media backup file.
 * @param sph   SADUMP partition header.
 * @param pos   Position of the SADUMP partition header within the file.
 * @returns     Error status.
 */
static kdump_status
open_common(kdump_ctx_t *ctx, unsigned fidx,
	    struct disk_set_info *dsi, struct disk_id *dmap,
	    const struct sadump_media_header *smh,
	    const struct sadump_part_header *sph, off_t pos)
{
	struct sadump_priv *sp;
	struct sadump_header sh;
	uint32_t block_size, set_disk_set;
	uint64_t used_device;
	const char *desc;
	off_t hdr_pos;
	kdump_status status;

	if (fidx == 0 && (status = init_sadump(ctx)) != KDUMP_OK)
		return status;

	if (smh && (status = check_media_part(ctx, smh, sph)) != KDUMP_OK)
		return status;

	sp = ctx->shared->fmtdata;
	used_device = dump64toh(ctx, sph->used_device);

	hdr_pos = pos;
	status = verify_magic_number(ctx, fidx, &hdr_pos);
	if (status != KDUMP_OK)
		return status;

	if (fidx == 0) {
		sp->block_size = hdr_pos - pos;
		memcpy(&dsi->sadump_id, &sph->sadump_id,
		       sizeof(struct efi_guid));
		memcpy(&dsi->disk_set_id, &sph->disk_set_id,
		       sizeof(struct efi_guid));
		memcpy(&dsi->time_stamp, &sph->time_stamp,
		       sizeof(struct efi_time));
	} else if (sp->block_size != hdr_pos - pos)
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "%s (current file %llu, previous %zd)",
				 "Block size mismatch",
				 (unsigned long long) (hdr_pos - pos),
				 sp->block_size);
	else if (memcmp(&dsi->sadump_id, &sph->sadump_id,
			sizeof(struct efi_guid)))
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "System ID mismatch");
	else if (memcmp(&dsi->disk_set_id, &sph->disk_set_id,
			sizeof(struct efi_guid)))
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "Disk set ID mismatch");
	else if (memcmp(&dsi->time_stamp, &sph->time_stamp,
			sizeof(struct efi_time)))
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "Timestamp mismatch");

	set_disk_set = smh ? 0 : dump32toh(ctx, sph->set_disk_set);
	if (set_disk_set == 0) {
		desc = smh
			? "SADUMP media backup"
			: "SADUMP single partition";
		if (get_num_files(ctx) > 1)
			return set_error(ctx, KDUMP_ERR_NOTIMPL,
					 "Multiple %s files not implemented",
					 desc);
	} else if (set_disk_set > get_num_files(ctx)) {
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "Disk #%" PRIu32 " found, but only %u file(s) provided",
				 set_disk_set, get_num_files(ctx));
	} else {
		struct disk_id *di = dmap + set_disk_set - 1;

		if (di->seen)
			return set_error(ctx, KDUMP_ERR_INVALID,
					 "Duplicate disk #%" PRIu32,
					 set_disk_set);

		status = process_vol_id(ctx, sph, dmap, set_disk_set);
		if (status != KDUMP_OK)
			return status;

		if (set_disk_set > 1) {
			/* disk contains only partition header + data */
			struct sadump_disk_extents *ext =
				&sp->ext[set_disk_set - 1];
			ext->data_pos = sp->block_size;
			ext->data_len = used_device - sp->block_size;
			ext->fidx = fidx;
			di->seen = true;
			return KDUMP_OK;
		}

		status = init_disk_set(ctx, fidx, &hdr_pos, dmap);
		if (status != KDUMP_OK)
			return status;

		dmap->seen = true;
		desc = "SADUMP disk set";
	}
	if (fidx == 0)
		set_file_description(ctx, desc);

	status = fcache_pread(ctx->shared->fcache, &sh, sizeof sh,
			      fidx, hdr_pos);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot read dump header");

	block_size = dump32toh(ctx, sh.block_size);
	if (block_size != sp->block_size)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "%s (header %" PRIu32 ", detected %zu)",
				 "Block size mismatch",
				 block_size, sp->block_size);

	status = setup_arch(ctx, fidx, hdr_pos + block_size,
			    dump32toh(ctx, sh.sub_hdr_size) * block_size,
			    dump32toh(ctx, sh.nr_cpus));
	if (status != KDUMP_OK)
		return status;

	if (dump32toh(ctx, sh.header_version) < 1)
		set_max_pfn(ctx, dump32toh(ctx, sh.max_mapnr));
	else
		set_max_pfn(ctx, dump64toh(ctx, sh.max_mapnr_64));

	dsi->bmp_pos = hdr_pos + sp->block_size * (
		1 +				   /* SADUMP header itself */
		dump32toh(ctx, sh.sub_hdr_size) +  /* arch-dependent header */
		dump32toh(ctx, sh.bitmap_blocks)); /* memory bitmap */
	sp->ext[0].data_pos = dsi->bmp_pos +
		sp->block_size * dump32toh(ctx, sh.dumpable_bitmap_blocks);
	sp->ext[0].data_len = used_device - sp->ext[0].data_pos;
	sp->ext[0].fidx = fidx;
	return KDUMP_OK;
}

/** Probe one file from a file set.
 * @param ctx   Dump file object.
 * @param fidx  File index in file cache.
 * @param dsi   Disk set info. Updated on success.
 * @param dmap  Disk identification (indexed by disk number).
 *              Updated on success.
 * @returns     Error status.
 */
static kdump_status
probe_file(kdump_ctx_t *ctx, unsigned fidx, struct disk_set_info *dsi,
	   struct disk_id *dmap)
{
	struct sadump_media_header smh;
	struct sadump_part_header sph;
	kdump_status status;

	/* Is this a single-partition or disk set SADUMP? */
	status = fcache_pread(ctx->shared->fcache, &sph, sizeof sph,
			      fidx, 0);
	if (status != KDUMP_OK)
		goto err;

	if (le32toh(sph.signature[0]) == SADUMP_PART_SIGNATURE0 &&
	    le32toh(sph.signature[1]) == SADUMP_PART_SIGNATURE1)
		return open_common(ctx, fidx, dsi, dmap, NULL, &sph, 0);

	/* No. Is this a media backup SADUMP? */
	status = fcache_pread(ctx->shared->fcache, &smh, sizeof smh,
			      fidx, 0);
	if (status != KDUMP_OK)
		goto err;

	status = fcache_pread(ctx->shared->fcache, &sph, sizeof sph,
			      fidx, DEFAULT_BLOCK_SIZE);
	if (status != KDUMP_OK)
		goto err;

	if (le32toh(sph.signature[0]) == SADUMP_PART_SIGNATURE0 &&
	    le32toh(sph.signature[1]) == SADUMP_PART_SIGNATURE1)
		return open_common(ctx, fidx, dsi, dmap, &smh, &sph,
				   DEFAULT_BLOCK_SIZE);

	/* Neither. So, it's not SADUMP. */
	return set_error(ctx, KDUMP_NOPROBE, "Unrecognized SADUMP signature");

 err:
	return set_error(ctx, status, "Cannot read dump header");
}


static kdump_status
sadump_probe(kdump_ctx_t *ctx)
{
	struct sadump_priv *sp;
	struct disk_set_info dsi;
	struct disk_id dmap[get_num_files(ctx)];
	kdump_bmp_t *bmp;
	unsigned fidx;
	kdump_status status;

	memset(dmap, 0, sizeof dmap);
	for (fidx = 0; fidx < get_num_files(ctx); ++fidx) {
		status = probe_file(ctx, fidx, &dsi, dmap);
		if (status != KDUMP_OK) {
			sadump_cleanup(ctx->shared);
			return set_error(ctx, status, "File #%u", fidx);
		}
	}
	sp = ctx->shared->fmtdata;

	status = read_bitmap(ctx, &sp->pfm, sp->ext[0].fidx,
			     dsi.bmp_pos, sp->ext[0].data_pos - dsi.bmp_pos);
	if (status != KDUMP_OK) {
		sadump_cleanup(ctx->shared);
		return status;
	}

	bmp = kdump_bmp_new(&sadump_bmp_ops);
	if (!bmp) {
		sadump_cleanup(ctx->shared);
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate file pagemap");
	}
	bmp->priv = ctx->shared;
	shared_incref_locked(ctx->shared);
	set_file_pagemap(ctx, bmp);

	return KDUMP_OK;
}

static void
sadump_cleanup(struct kdump_shared *shared)
{
	struct sadump_priv *sp = shared->fmtdata;

	if (sp) {
		free(sp->pfm.regions);
		free(sp);
		shared->fmtdata = NULL;
	}
}

const struct format_ops sadump_ops = {
	.name = "sadump",
	.probe = sadump_probe,
	.get_page = sadump_get_page,
	.put_page = cache_put_page,
	.realloc_caches = def_realloc_caches,
	.cleanup = sadump_cleanup,
};
