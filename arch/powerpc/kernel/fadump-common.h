/*
 * Firmware-Assisted Dump internal code.
 *
 * Copyright 2011, IBM Corporation
 * Author: Mahesh Salgaonkar <mahesh@linux.ibm.com>
 *
 * Copyright 2019, IBM Corp.
 * Author: Hari Bathini <hbathini@linux.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __PPC64_FA_DUMP_INTERNAL_H__
#define __PPC64_FA_DUMP_INTERNAL_H__

/*
 * The RMA region will be saved for later dumping when kernel crashes.
 * RMA is Real Mode Area, the first block of logical memory address owned
 * by logical partition, containing the storage that may be accessed with
 * translate off.
 */
#define RMA_START	0x0
#define RMA_END		(ppc64_rma_size)

/*
 * On some Power systems where RMO is 128MB, it still requires minimum of
 * 256MB for kernel to boot successfully. When kdump infrastructure is
 * configured to save vmcore over network, we run into OOM issue while
 * loading modules related to network setup. Hence we need additional 64M
 * of memory to avoid OOM issue.
 */
#define MIN_BOOT_MEM	(((RMA_END < (0x1UL << 28)) ? (0x1UL << 28) : RMA_END) \
			+ (0x1UL << 26))

/* The upper limit percentage for user specified boot memory size (25%) */
#define MAX_BOOT_MEM_RATIO			4

#define memblock_num_regions(memblock_type)	(memblock.memblock_type.cnt)

/* Alignment per CMA requirement. */
#define FADUMP_CMA_ALIGNMENT	(PAGE_SIZE <<				\
				 max_t(unsigned long, MAX_ORDER - 1,	\
				 pageblock_order))

/* FAD commands */
#define FADUMP_REGISTER			1
#define FADUMP_UNREGISTER		2
#define FADUMP_INVALIDATE		3

/* Firmware-Assited Dump platforms */
enum fadump_platform_type {
	FADUMP_PLATFORM_UNKNOWN = 0,
	FADUMP_PLATFORM_PSERIES,
	FADUMP_PLATFORM_POWERNV,
};

/*
 * Copy the ascii values for first 8 characters from a string into u64
 * variable at their respective indexes.
 * e.g.
 *  The string "FADMPINF" will be converted into 0x4641444d50494e46
 */
static inline u64 fadump_str_to_u64(const char *str)
{
	u64 val = 0;
	int i;

	for (i = 0; i < sizeof(val); i++)
		val = (*str) ? (val << 8) | *str++ : val << 8;
	return val;
}

#define FADUMP_CPU_UNKNOWN		(~((u32)0))

#define FADUMP_CRASH_INFO_MAGIC		fadump_str_to_u64("FADMPINF")

/* fadump crash info structure */
struct fadump_crash_info_header {
	u64		magic_number;
	u64		elfcorehdr_addr;
	u32		crashing_cpu;
	struct pt_regs	regs;
	struct cpumask	online_mask;
};

struct fadump_memory_range {
	unsigned long long	base;
	unsigned long long	size;
};

/* Platform specific callback functions */
struct fadump_ops;

/*
 * Amount of memory (1024MB) to skip before making another attempt at
 * reserving memory (after the previous attempt to reserve memory for
 * FADump failed due to memory holes and/or reserved ranges) to reduce
 * the likelihood of memory reservation failure.
 */
#define FADUMP_OFFSET_SIZE			0x40000000U

/* Maximum no. of reserved ranges supported for processing. */
#define FADUMP_MAX_RESERVED_RANGES		128

/* Maximum number of memory regions kernel supports */
#define FADUMP_MAX_MEM_REGS			128

/* Firmware-assisted dump configuration details. */
struct fw_dump {
	unsigned long	reserve_dump_area_start;
	unsigned long	reserve_dump_area_size;
	/* cmd line option during boot */
	unsigned long	reserve_bootvar;

	/*
	 * Start address of preserve area. This memory is reserved
	 * permanently (production or capture kernel) for FADump.
	 */
	unsigned long	preserv_area_start;

	unsigned long	cpu_state_data_size;
	unsigned long	hpte_region_size;

	unsigned long	boot_memory_size;
	unsigned long	boot_mem_dest_addr;
	unsigned long	boot_mem_regs_cnt;
	unsigned long	boot_mem_addr[FADUMP_MAX_MEM_REGS];
	unsigned long	boot_mem_size[FADUMP_MAX_MEM_REGS];
	unsigned long	boot_mem_top;

	unsigned long	fadumphdr_addr;
	unsigned long	cpu_notes_buf;
	unsigned long	cpu_notes_buf_size;

	/*
	 * Maximum size supported by firmware to copy from source to
	 * destination address per entry.
	 */
	unsigned long	max_copy_size;
	u64		kernel_metadata;

	int		ibm_configure_kernel_dump;

	unsigned long	fadump_enabled:1;
	unsigned long	fadump_supported:1;
	unsigned long	dump_active:1;
	unsigned long	dump_registered:1;
	unsigned long	nocma:1;

	enum fadump_platform_type	fadump_platform;
	struct fadump_ops		*ops;
};

struct fadump_ops {
	ulong	(*init_fadump_mem_struct)(struct fw_dump *fadump_config);
	ulong	(*get_kernel_metadata_size)(void);
	int	(*setup_kernel_metadata)(struct fw_dump *fadump_config);
	int	(*register_fadump)(struct fw_dump *fadump_config);
	int	(*unregister_fadump)(struct fw_dump *fadump_config);
	int	(*invalidate_fadump)(struct fw_dump *fadump_config);
	int	(*process_fadump)(struct fw_dump *fadump_config);
	void	(*fadump_region_show)(struct fw_dump *fadump_config,
				      struct seq_file *m);
	void	(*fadump_trigger)(struct fadump_crash_info_header *fdh,
				  const char *msg);
};

/* Helper functions */
void *fadump_cpu_notes_buf_alloc(unsigned long size);
void fadump_cpu_notes_buf_free(unsigned long vaddr, unsigned long size);
u32 *fadump_regs_to_elf_notes(u32 *buf, struct pt_regs *regs);
void fadump_update_elfcore_header(struct fw_dump *fadump_config, char *bufp);
int is_fadump_boot_mem_contiguous(struct fw_dump *fadump_conf);
int is_fadump_reserved_mem_contiguous(struct fw_dump *fadump_conf);

#ifdef CONFIG_PPC_PSERIES
extern int rtas_fadump_dt_scan(struct fw_dump *fadump_config, ulong node);
#else
static inline int rtas_fadump_dt_scan(struct fw_dump *fadump_config, ulong node)
{
	return 1;
}
#endif

#ifdef CONFIG_PPC_POWERNV
extern int opal_fadump_dt_scan(struct fw_dump *fadump_config, ulong node);
#else
static inline int opal_fadump_dt_scan(struct fw_dump *fadump_config, ulong node)
{
	return 1;
}
#endif

#endif /* __PPC64_FA_DUMP_INTERNAL_H__ */
