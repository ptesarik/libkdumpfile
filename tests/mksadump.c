/* SADUMP format test suite.
   Copyright (C) 2022 Petr Tesarik <ptesarik@suse.com>

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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "config.h"
#include "testutil.h"
#include "sadump.h"

#define WS_CHARS	" \f\n\r\t\v"

#define EFI_UNSPECIFIED_TIMEZONE 0x07FF
#define EFI_TIME_ADJUST_DAYLIGHT 0x01
#define EFI_TIME_IN_DAYLIGHT     0x02

#define DEFAULT_BLOCK_SIZE	4096

struct page_data_sadump {
	FILE *f;

	unsigned char *page_bitmap;
	unsigned char *dumpable_bitmap;
	unsigned long total_ram_blocks;
	unsigned long dumped_ram_blocks;

	unsigned long first_pfn_idx;
	unsigned long long addr;
	bool exclude;

	enum {
		data_vol_info,
		data_apic_state,
		data_cpu_state,
		data_page,
	} data_type;
	off_t data_pos;

	off_t vol_info_pos;
	off_t apic_state_pos;
	off_t cpu_state_pos;
	off_t page_data_pos;
};

static char *sadump_type_str;
enum {
	sadump_single,
	sadump_diskset,
	sadump_media,
} sadump_type;

static endian_t be = data_le;
static unsigned long long block_size = DEFAULT_BLOCK_SIZE;
static unsigned long long first_pfn;
static unsigned long long last_pfn = ULLONG_MAX;

static char *timestamp;
struct efi_time efi_timestamp;

static char *system_id;
struct efi_guid guid_system;

static char *disk_set_id;
struct efi_guid guid_disk_set;

static char *volume_id;
struct efi_guid guid_volume;

static unsigned long long disk_num;
static unsigned long long set_disk_set;

static unsigned long long reboot_timeout = 60;

static unsigned long long max_mapnr;
static unsigned long long nr_cpus = 1;
static unsigned long long current_cpu;

static unsigned long long device_blocks;

static char *data_file;

static const struct param param_array[] = {
	/* basic parameters */
	PARAM_STRING("type", sadump_type_str),
	PARAM_NUMBER("block_size", block_size),
	PARAM_NUMBER("first_pfn", first_pfn),
	PARAM_NUMBER("last_pfn", last_pfn),

	/* identification */
	PARAM_STRING("timestamp", timestamp),
	PARAM_STRING("system_id", system_id),
	PARAM_STRING("disk_set_id", disk_set_id),
	PARAM_STRING("volume_id", volume_id),

	/* partition header */
	PARAM_NUMBER("reboot_timeout", reboot_timeout),
	PARAM_NUMBER("set_disk_set", set_disk_set),

	/* disk set header */
	PARAM_NUMBER("disk_num", disk_num),

	/* SADUMP header */
	PARAM_NUMBER("max_mapnr", max_mapnr),
	PARAM_NUMBER("nr_cpus", nr_cpus),
	PARAM_NUMBER("current_cpu", current_cpu),
	PARAM_NUMBER("device_blocks", device_blocks),

	/* data file */
	PARAM_STRING("DATA", data_file)
};

static const struct params params = {
	ARRAY_SIZE(param_array),
	param_array
};

static int
current_timestamp(struct efi_time *stamp)
{
	struct timespec ts;
	struct tm tm;

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		perror("clock_gettime");
		return TEST_ERR;
	}
	tzset();
	localtime_r(&ts.tv_sec, &tm);
	stamp->year = tm.tm_year + 1900;
	stamp->month = tm.tm_mon + 1;
	stamp->day = tm.tm_mday;
	stamp->hour = tm.tm_hour;
	stamp->minute = tm.tm_min;
	stamp->second = tm.tm_sec;
	stamp->nanosecond = ts.tv_nsec;
	stamp->timezone = timezone / 60;
	stamp->daylight =
		(daylight ? EFI_TIME_ADJUST_DAYLIGHT : 0) |
		(tm.tm_isdst ? EFI_TIME_IN_DAYLIGHT : 0);

	return TEST_OK;
}

static int
parse_timestamp(struct efi_time *stamp, const char *spec)
{
	unsigned year, month, day, hour, min, sec, nsec, daylight;
	unsigned tzhour, tzmin;
	char tzsign;
	long tz;
	int rest;
	const char *p = spec;

	if (sscanf(p, "%4u-%2u-%2u %2u:%2u:%2u%n",
		   &year, &month, &day, &hour, &min, &sec, &rest) != 6 ||
	    year < 1900 || year > 9999 ||
	    month < 1 || month > 12 ||
	    day < 1 || day > 31 ||
	    hour > 23 || min > 59 || sec > 59)
		goto err_invalid;
	p += rest;
	if (*p == '.') {
		++p;
		if (sscanf(p, "%u%n", &nsec, &rest) != 1 || rest > 9)
			goto err_invalid;
		p += rest;
		for (; rest < 9; ++rest)
			nsec *= 10;
	} else
		nsec = 0;

	while (isspace(*p))
		++p;
	if ((*p == '+' || *p == '-') &&
	    sscanf(p, "%c%2u%2u%n", &tzsign, &tzhour, &tzmin, &rest) == 3) {
		tz = tzhour * 60 + tzmin;
		if (tzsign == '-')
			tz = -tz;
		if (tz < -1440 || tz > 1440) {
			fprintf(stderr, "Invalid time zone: %s\n", p);
			return TEST_ERR;
		}
		p += rest;
	} else
		tz = EFI_UNSPECIFIED_TIMEZONE;

	while (isspace(*p))
		++p;
	if (!strncasecmp(p, "DST", 3)) {
		daylight = EFI_TIME_ADJUST_DAYLIGHT | EFI_TIME_IN_DAYLIGHT;
		p += 3;
	} else if (!strncasecmp(p, "NODST", 5)) {
		daylight = 0;
		p += 5;
	} else
		daylight = EFI_TIME_ADJUST_DAYLIGHT;

	while (isspace(*p))
		++p;
	if (*p)
		goto err_invalid;

	memset(stamp, 0, sizeof *stamp);
	stamp->year = year;
	stamp->month = month;
	stamp->day = day;
	stamp->hour = hour;
	stamp->minute = min;
	stamp->second = sec;
	stamp->nanosecond = nsec;
	stamp->timezone = tz;
	stamp->daylight = daylight;
	return TEST_OK;

 err_invalid:
	fprintf(stderr, "Invalid time stamp: %s\n", spec);
	return TEST_ERR;
}

static int
parse_guid(struct efi_guid *guid, const char *spec)
{
	unsigned char bytes[16];
	unsigned nums[16];
	unsigned i;
	int rest;

	if (sscanf(spec, "%2x%2x%2x%2x-%2x%2x-%2x%2x-%2x%2x-%2x%2x%2x%2x%2x%2x%n",
		   &nums[0], &nums[1], &nums[2], &nums[3],
		   &nums[4], &nums[5], &nums[6], &nums[7],
		   &nums[8], &nums[9], &nums[10], &nums[11],
		   &nums[12], &nums[13], &nums[14], &nums[15],
		   &rest) != 16)
		goto err_invalid;
	while (isspace(spec[rest]))
		++rest;
	if (spec[rest])
		goto err_invalid;

	for (i = 0; i < 16; ++i)
		bytes[i] = nums[i];
	memcpy(guid, bytes, sizeof *guid);
	return TEST_OK;

 err_invalid:
	fprintf(stderr, "Invalid GUID: %s\n", spec);
	return TEST_ERR;
}

static int
parseheader(struct page_data *pg, char *p)
{
	struct page_data_sadump *pds = pg->priv;
	char *tok, *endp;

	tok = strtok(p, WS_CHARS);
	if (!tok) {
		fprintf(stderr, "Invalid data header: %s\n", p);
		return TEST_ERR;
	}

	if (!strcmp(tok, "volume")) {
		pds->data_type = data_vol_info;
		pds->data_pos = pds->vol_info_pos;
	} else if (!strcmp(tok, "apic")) {
		pds->data_type = data_apic_state;
		pds->data_pos = pds->apic_state_pos;
	} else if (!strcmp(tok, "cpu")) {
		unsigned long cpu;

		tok = strtok(NULL, WS_CHARS);
		if (!tok) {
			fprintf(stderr, "Missing cpu number!\n");
			return TEST_ERR;
		}
		cpu = strtoul(tok, &endp, 0);
		if (*endp || cpu >= nr_cpus) {
			fprintf(stderr, "Invalid cpu number: %s\n", tok);
			return TEST_ERR;
		}

		pds->data_type = data_cpu_state;
		pds->data_pos = pds->cpu_state_pos +
			cpu * sizeof(struct sadump_smram_cpu_state);
	} else {
		pds->addr = strtoull(tok, &endp, 0);
		if (*endp) {
			fprintf(stderr, "Invalid address: %s\n", tok);
			return TEST_ERR;
		}

		pds->exclude = false;
		while ( (tok = strtok(NULL, WS_CHARS)) ) {
			if (!strcmp(tok, "exclude"))
				pds->exclude = true;
			else {
				fprintf(stderr, "Invalid flag: %s\n", tok);
				return TEST_ERR;
			}
		}

		pds->data_type = data_page;
		pds->data_pos = pds->page_data_pos;
	}

	return TEST_OK;
}

static int
markpage(struct page_data *pg)
{
	struct page_data_sadump *pds = pg->priv;
	unsigned long long pfn;
	size_t idx;

	if (pds->data_type != data_page)
		return TEST_OK;

	pfn = pds->addr / block_size;
	if (pfn >= max_mapnr) {
		fprintf(stderr, "PFN too large: %llu\n", pfn);
		return TEST_ERR;
	}

	idx = pfn >> 3;
	pds->page_bitmap[idx] |= 1U << (7 - (pfn & 7));
	if (!pds->exclude) {
		pds->dumpable_bitmap[idx] |= 1U << (7 - (pfn & 7));
		if (pfn >= first_pfn && pfn <= last_pfn)
			++pds->dumped_ram_blocks;
	}

	++pds->total_ram_blocks;

	return TEST_OK;
}

static inline unsigned
bitcount(unsigned x)
{
	return __builtin_popcount(x);
}

unsigned long
bitmap_index(const unsigned char *bmp, unsigned long bit)
{
	unsigned long ret = 0;
	unsigned char mask;
	while (bit >= 8) {
		ret += bitcount(*bmp++);
		bit -= 8;
	}
	for (mask = 0x80; bit; --bit, mask >>= 1)
		if (*bmp & mask)
			++ret;
	return ret;
}

static int
writepage(struct page_data *pg)
{
	struct page_data_sadump *pds = pg->priv;

	if (!pg->len)
		return TEST_OK;

	if (pds->data_type == data_page) {
		unsigned long long pfn;
		unsigned long idx;

		pfn = pds->addr / block_size;
		if (pfn < first_pfn || pfn > last_pfn)
			return TEST_OK;
		idx = bitmap_index(pds->dumpable_bitmap, pfn);
		idx -= pds->first_pfn_idx;
		pds->data_pos += idx * block_size;
	} else if (sadump_type == sadump_diskset && set_disk_set != 1)
		return TEST_OK;

	if (fseek(pds->f, pds->data_pos, SEEK_SET) != 0) {
		perror("seek data");
		return TEST_ERR;
	}
	if (fwrite(pg->buf, pg->len, 1, pds->f) != 1) {
		perror("write data");
		return TEST_ERR;
	}

	return TEST_OK;
}

static void
htodump_efi_time(endian_t be, struct efi_time *t)
{
	t->year = htodump16(be, t->year);
	t->nanosecond = htodump32(be, t->nanosecond);
	t->timezone = htodump16(be, t->timezone);
}

static void
htodump_media_header(endian_t be, struct sadump_media_header *smh)
{
	htodump_efi_time(be, &smh->time_stamp);
}

static void
htodump_part_header(endian_t be, struct sadump_part_header *sph)
{
	unsigned i;

	sph->signature[0] = htodump32(be, sph->signature[0]);
	sph->signature[1] = htodump32(be, sph->signature[1]);
	sph->enable = htodump32(be, sph->enable);
	sph->reboot = htodump32(be, sph->reboot);
	sph->compress = htodump32(be, sph->compress);
	sph->recycle = htodump32(be, sph->recycle);
	for (i = 0; i < ARRAY_SIZE(sph->label); ++i)
		sph->label[i] = htodump32(be, sph->label[i]);
	htodump_efi_time(be, &sph->time_stamp);
	sph->set_disk_set = htodump32(be, sph->set_disk_set);
	sph->used_device = htodump64(be, sph->used_device);
}

static void
htodump_disk_set_header(endian_t be, struct sadump_disk_set_header *sdsh)
{
	sdsh->disk_set_header_size = htodump32(be, sdsh->disk_set_header_size);
	sdsh->disk_num = htodump32(be, sdsh->disk_num);
	sdsh->disk_set_size = htodump64(be, sdsh->disk_set_size);
}

static void
htodump_sadump_header(endian_t be, struct sadump_header *sh)
{
	sh->header_version = htodump32(be, sh->header_version);
	htodump_efi_time(be, &sh->timestamp);
	sh->status = htodump32(be, sh->status);
	sh->compress = htodump32(be, sh->compress);
	sh->block_size = htodump32(be, sh->block_size);
	sh->extra_hdr_size = htodump32(be, sh->extra_hdr_size);
	sh->sub_hdr_size = htodump32(be, sh->sub_hdr_size);
	sh->bitmap_blocks = htodump32(be, sh->bitmap_blocks);
	sh->dumpable_bitmap_blocks = htodump32(be, sh->dumpable_bitmap_blocks);
	sh->max_mapnr = htodump32(be, sh->max_mapnr);
	sh->total_ram_blocks = htodump32(be, sh->total_ram_blocks);
	sh->device_blocks = htodump32(be, sh->device_blocks);
	sh->written_blocks = htodump32(be, sh->written_blocks);
	sh->current_cpu = htodump32(be, sh->current_cpu);
	sh->nr_cpus = htodump32(be, sh->nr_cpus);
	sh->max_mapnr_64 = htodump64(be, sh->max_mapnr_64);
	sh->total_ram_blocks_64 = htodump64(be, sh->total_ram_blocks_64);
	sh->device_blocks_64 = htodump64(be, sh->device_blocks_64);
	sh->written_blocks_64 = htodump64(be, sh->written_blocks_64);
}

static int
writedump(FILE *f)
{
	struct sadump_media_header smh = {
		.sadump_id = guid_system,
		.disk_set_id = guid_disk_set,
		.time_stamp = efi_timestamp,
		.sequential_num = set_disk_set,
		.term_cord = 0,		   /* observed in all sample files */
		.disk_set_header_size = 0, /* observed in all sample files */
		.disks_in_use = 0,	   /* observed in all sample files */
	};
	struct sadump_part_header sph = {
		.signature = {
			SADUMP_PART_SIGNATURE0,
			SADUMP_PART_SIGNATURE1,
		},
		.enable = 1,
		.reboot = reboot_timeout,
		.compress = 1, /* observed in all sample files */
		.recycle = 1,
		.sadump_id = guid_system,
		.disk_set_id = guid_disk_set,
		.vol_id = guid_volume,
		.time_stamp = efi_timestamp,
		.set_disk_set = set_disk_set,
	};
	struct sadump_disk_set_header sdsh = {
		.disk_num = disk_num,
		.disk_set_size = 0, /* FIXME! */
	};
	struct sadump_header sh = {
		.signature = SADUMP_SIGNATURE,
		.header_version = 1,
		.timestamp = efi_timestamp,
		.status = 0,   /* observed in all sample files */
		.compress = 0, /* observed in all sample files */
		.block_size = block_size,
		.extra_hdr_size = 0,
		.max_mapnr = max_mapnr,
		.current_cpu = current_cpu,
		.nr_cpus = nr_cpus,
		.max_mapnr_64 = max_mapnr,
	};
	struct page_data_sadump pds;
	struct page_data pg;
	off_t part_hdr_pos;
	off_t sadump_hdr_pos;
	off_t sub_hdr_pos;
	off_t sub_hdr_size;
	size_t bmp_size;
	off_t used_device;
	int rc;

	if (!data_file)
		return TEST_OK;

	part_hdr_pos = 0;
	if (sadump_type == sadump_media)
		part_hdr_pos += block_size;

	sadump_hdr_pos = part_hdr_pos + block_size;
	if (sadump_type == sadump_diskset && set_disk_set == 1) {
		sadump_hdr_pos +=
			sizeof(struct sadump_disk_set_header) +
			sizeof(struct sadump_volume_info) * disk_num;
		sadump_hdr_pos += block_size - 1;
		sadump_hdr_pos -= sadump_hdr_pos % block_size;
	}

	if (sadump_type != sadump_diskset || set_disk_set == 1) {
		sub_hdr_pos = sadump_hdr_pos + block_size;
		sub_hdr_size = sizeof(uint32_t) +
			nr_cpus * (sizeof(struct sadump_apic_state) +
				   sizeof(struct sadump_smram_cpu_state));
		sub_hdr_size += block_size - 1;
		sub_hdr_size -= sub_hdr_size % block_size;
	} else {
		sub_hdr_pos = sadump_hdr_pos;
		sub_hdr_size = 0;
	}

	bmp_size = (max_mapnr + 7) / 8;
	bmp_size += block_size - 1;
	bmp_size -= bmp_size % block_size;

	memset(&pds, 0, sizeof pds);
	pds.f = f;
	if (! (pds.page_bitmap = calloc(bmp_size, 1)) ) {
		perror("page bitmap");
		return TEST_ERR;
	}
	if (! (pds.dumpable_bitmap = calloc(bmp_size, 1)) ) {
		perror("dumpable bitmap");
		return TEST_ERR;
	}
	pds.vol_info_pos = part_hdr_pos + block_size +
		sizeof(struct sadump_disk_set_header);
	pds.apic_state_pos = sub_hdr_pos + sizeof(uint32_t);
	pds.cpu_state_pos = pds.apic_state_pos +
		nr_cpus * sizeof(struct sadump_apic_state);
	pds.page_data_pos = sub_hdr_pos + sub_hdr_size;
	if (sadump_type != sadump_diskset || set_disk_set == 1)
		pds.page_data_pos += 2 * bmp_size;

	pg.endian = be;
	pg.priv = &pds;
	pg.parse_hdr = parseheader;
	pg.write_page = markpage;

	rc = process_data(&pg, data_file);
	if (rc != TEST_OK)
		return rc;

	pds.first_pfn_idx = bitmap_index(pds.dumpable_bitmap, first_pfn);
	used_device = pds.page_data_pos +
		block_size * pds.dumped_ram_blocks;

	/* finalize media header */
	htodump_media_header(be, &smh);

	/* finalize partition header */
	sph.used_device = used_device;
	htodump_part_header(be, &sph);

	/* finalize disk set header */
	sdsh.disk_set_header_size =
		(sadump_hdr_pos - part_hdr_pos) / block_size - 1;
	htodump_disk_set_header(be, &sdsh);

	/* finalize SADUMP header */
	sh.sub_hdr_size = sub_hdr_size / block_size;
	sh.bitmap_blocks = bmp_size / block_size;
	sh.dumpable_bitmap_blocks = bmp_size / block_size;
	sh.total_ram_blocks = sh.total_ram_blocks_64 = pds.total_ram_blocks;
	sh.written_blocks = sh.written_blocks_64 = used_device / block_size;
	if (!device_blocks)
		device_blocks = sh.written_blocks;
	sh.device_blocks = sh.device_blocks_64 = device_blocks;
	htodump_sadump_header(be, &sh);

	if (sadump_type == sadump_media) {
		if (fseek(f, 0, SEEK_SET)) {
			perror("seek media backup header");
			return TEST_ERR;
		}
		if (fwrite(&smh, sizeof smh, 1, f) != 1) {
			perror("write media backup header");
			return TEST_ERR;
		}
	}

	if (fseek(f, part_hdr_pos, SEEK_SET)) {
		perror("seek partition header");
		return TEST_ERR;
	}
	if (fwrite(&sph, sizeof sph, 1, f) != 1) {
		perror("write partition header");
		return TEST_ERR;
	}

	uint32_t magic = 0;
	while (ftell(f) != part_hdr_pos + block_size) {
		uint32_t rawmagic = htodump32(be, magic);
		if (fwrite(&rawmagic, sizeof rawmagic, 1, f) != 1) {
			perror("write partition header magic");
			return TEST_ERR;
		}
		magic = (magic + 7) * 11;
	}

	if (sadump_type == sadump_diskset) {
		if (fseek(f, part_hdr_pos + block_size, SEEK_SET)) {
			perror("seek diskset header");
			return TEST_ERR;
		}
		if (fwrite(&sdsh, sizeof sdsh, 1, f) != 1) {
			perror("write diskset header");
			return TEST_ERR;
		}
	}

	if (sadump_type != sadump_diskset || set_disk_set == 1) {
		if (fseek(f, sadump_hdr_pos, SEEK_SET)) {
			perror("seek sadump header");
			return TEST_ERR;
		}
		if (fwrite(&sh, sizeof sh, 1, f) != 1) {
			perror("write sadump header");
			return TEST_ERR;
		}

		if (sub_hdr_size) {
			uint32_t sz = nr_cpus *
				sizeof(struct sadump_smram_cpu_state);
			sz = htodump32(be, sz);
			if (fseek(f, sub_hdr_pos, SEEK_SET)) {
				perror("seek sub-header");
				return TEST_ERR;
			}
			if (fwrite(&sz, sizeof sz, 1, f) != 1) {
				perror("write CPU state size");
				return TEST_ERR;
			}
		}

		/* write bitmaps */
		if (fseek(f, sub_hdr_pos + sub_hdr_size, SEEK_SET)) {
			perror("seek page bitmap");
			return TEST_ERR;
		}
		if (fwrite(pds.page_bitmap, 1, bmp_size, f) != bmp_size) {
			perror("write page bitmap");
			return TEST_ERR;
		}

		if (fseek(f, sub_hdr_pos + sub_hdr_size + bmp_size, SEEK_SET)) {
			perror("seek dumpable bitmap");
			return TEST_ERR;
		}
		if (fwrite(pds.dumpable_bitmap, 1, bmp_size, f) != bmp_size) {
			perror("write dumpable bitmap");
			return TEST_ERR;
		}
	}

	pg.write_page = writepage;
	return process_data(&pg, data_file);
}

static int
create_file(const char *name)
{
	FILE *f;
	int rc;

	if (!sadump_type_str || !strcmp(sadump_type_str, "single"))
		sadump_type = sadump_single;
	else if (!strcmp(sadump_type_str, "diskset"))
		sadump_type = sadump_diskset;
	else if (!strcmp(sadump_type_str, "media"))
		sadump_type = sadump_media;
	else {
		fprintf(stderr, "Unsupported file type: %s\n",
			sadump_type_str);
		return TEST_ERR;
	}

	f = fopen(name, "w");
	if (!f) {
		perror("Cannot create output");
		return TEST_ERR;
	}

	rc = writedump(f);
	if (fclose(f) != 0) {
		perror("Error closing output");
		rc = TEST_ERR;
	}

	return rc;
}

int
main(int argc, char **argv)
{
	int rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <dump>\n", argv[0]);
		return TEST_ERR;
	}

	rc = parse_params_file(&params, stdin);
	if (rc != TEST_OK)
		return rc;

	memset(&efi_timestamp, 0, sizeof efi_timestamp);
	rc = timestamp
		? parse_timestamp(&efi_timestamp, timestamp)
		: current_timestamp(&efi_timestamp);
	if (rc != TEST_OK)
		return rc;

	if (system_id) {
		rc = parse_guid(&guid_system, system_id);
		if (rc != TEST_OK)
			return rc;
	}

	if (disk_set_id) {
		rc = parse_guid(&guid_disk_set, disk_set_id);
		if (rc != TEST_OK)
			return rc;
	}

	if (volume_id) {
		rc = parse_guid(&guid_volume, volume_id);
		if (rc != TEST_OK)
			return rc;
	}

	rc = create_file(argv[1]);
	if (rc != TEST_OK)
		return rc;

	return TEST_OK;
}
