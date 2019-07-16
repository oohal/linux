/*
 * Firmware-Assisted Dump support on POWER platform (OPAL).
 *
 * Copyright 2019, IBM Corp.
 * Author: Hari Bathini <hbathini@linux.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#undef DEBUG
#define pr_fmt(fmt) "opal fadump: " fmt

#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/mm.h>
#include <linux/crash_dump.h>

#include <asm/page.h>
#include <asm/opal.h>

#include "../../kernel/fadump-common.h"
#include "opal-fadump.h"

static const struct opal_fadump_mem_struct *opal_fdm_active;
static const struct opal_mpipl_fadump *opal_cpu_metadata;
static struct opal_fadump_mem_struct *opal_fdm;

static void opal_fadump_update_config(struct fw_dump *fadump_conf,
				      const struct opal_fadump_mem_struct *fdm)
{
	pr_debug("Boot memory regions count: %d\n", fdm->region_cnt);

	/*
	 * The destination address of the first boot memory region is the
	 * destination address of boot memory regions.
	 */
	fadump_conf->boot_mem_dest_addr = fdm->rgn[0].dest;
	pr_debug("Destination address of boot memory regions: %#016lx\n",
		 fadump_conf->boot_mem_dest_addr);

	fadump_conf->fadumphdr_addr = fdm->fadumphdr_addr;

	/* Start address of preserve area (permanent reservation) */
	fadump_conf->preserv_area_start = fadump_conf->boot_mem_dest_addr;
	pr_debug("Preserve area start address: 0x%lx\n",
		 fadump_conf->preserv_area_start);
}

/*
 * This function is called in the capture kernel to get configuration details
 * from metadata setup by the first kernel.
 */
static void opal_fadump_get_config(struct fw_dump *fadump_conf,
				   const struct opal_fadump_mem_struct *fdm)
{
	unsigned long base, size, last_end, hole_size;
	int i;

	if (!fadump_conf->dump_active)
		return;

	last_end = 0;
	hole_size = 0;
	fadump_conf->boot_memory_size = 0;

	if (fdm->region_cnt)
		pr_debug("Boot memory regions:\n");

	for (i = 0; i < fdm->region_cnt; i++) {
		base = fdm->rgn[i].src;
		size = fdm->rgn[i].size;
		pr_debug("\t%d. base: 0x%lx, size: 0x%lx\n",
			 (i + 1), base, size);

		fadump_conf->boot_mem_addr[i] = base;
		fadump_conf->boot_mem_size[i] = size;
		fadump_conf->boot_memory_size += size;
		hole_size += (base - last_end);

		last_end = base + size;
	}

	fadump_conf->boot_mem_top = (fadump_conf->boot_memory_size + hole_size);
	fadump_conf->boot_mem_regs_cnt = fdm->region_cnt;
	opal_fadump_update_config(fadump_conf, fdm);
}

static ulong opal_fadump_init_mem_struct(struct fw_dump *fadump_conf)
{
	ulong addr = fadump_conf->reserve_dump_area_start;
	int i;

	opal_fdm = __va(fadump_conf->kernel_metadata);
	opal_fdm->version = OPAL_FADUMP_VERSION;
	opal_fdm->region_cnt = 0;
	opal_fdm->registered_regions = 0;

	/* RMA regions */
	for (i = 0; i < fadump_conf->boot_mem_regs_cnt; i++) {
		opal_fdm->rgn[i].src	= fadump_conf->boot_mem_addr[i];
		opal_fdm->rgn[i].dest	= addr;
		opal_fdm->rgn[i].size	= fadump_conf->boot_mem_size[i];

		opal_fdm->region_cnt++;
		addr += fadump_conf->boot_mem_size[i];
	}

	/*
	 * Kernel metadata is passed to f/w and retrieved in capture kerenl.
	 * So, use it to save fadump header address instead of calculating it.
	 */
	opal_fdm->fadumphdr_addr = (opal_fdm->rgn[0].dest +
				    fadump_conf->boot_memory_size);

	opal_fadump_update_config(fadump_conf, opal_fdm);

	return addr;
}

static ulong opal_fadump_get_kernel_metadata_size(void)
{
	ulong size = sizeof(struct opal_fadump_mem_struct);

	size = PAGE_ALIGN(size);
	return size;
}

static int opal_fadump_setup_kernel_metadata(struct fw_dump *fadump_conf)
{
	int err = 0;
	s64 ret;

	/*
	 * Use the last page(s) in FADump memory reservation for
	 * kernel metadata.
	 */
	fadump_conf->kernel_metadata = (fadump_conf->reserve_dump_area_start +
					fadump_conf->reserve_dump_area_size -
					opal_fadump_get_kernel_metadata_size());
	pr_info("Kernel metadata addr: %llx\n", fadump_conf->kernel_metadata);

	/*
	 * Register metadata address with f/w. Can be retrieved in
	 * the capture kernel.
	 */
	ret = opal_mpipl_register_tag(OPAL_MPIPL_TAG_KERNEL,
				      fadump_conf->kernel_metadata);
	if (ret != OPAL_SUCCESS) {
		pr_err("Failed to set kernel metadata tag!\n");
		err = -EPERM;
	}

	return err;
}

static int opal_fadump_register_fadump(struct fw_dump *fadump_conf)
{
	int i, err = -EIO;
	s64 rc;

	for (i = 0; i < opal_fdm->region_cnt; i++) {
		rc = opal_mpipl_update(OPAL_MPIPL_ADD_RANGE,
				       opal_fdm->rgn[i].src,
				       opal_fdm->rgn[i].dest,
				       opal_fdm->rgn[i].size);
		if (rc != OPAL_SUCCESS)
			break;

		opal_fdm->registered_regions++;
	}

	switch (rc) {
	case OPAL_SUCCESS:
		pr_info("Registration is successful!\n");
		fadump_conf->dump_registered = 1;
		err = 0;
		break;
	case OPAL_UNSUPPORTED:
		pr_err("Support not available.\n");
		fadump_conf->fadump_supported = 0;
		fadump_conf->fadump_enabled = 0;
		break;
	case OPAL_INTERNAL_ERROR:
		pr_err("Failed to register. Hardware Error(%lld).\n", rc);
		break;
	case OPAL_PARAMETER:
		pr_err("Failed to register. Parameter Error(%lld).\n", rc);
		break;
	case OPAL_PERMISSION:
		pr_err("Already registered!\n");
		fadump_conf->dump_registered = 1;
		err = -EEXIST;
		break;
	default:
		pr_err("Failed to register. Unknown Error(%lld).\n", rc);
		break;
	}

	return err;
}

static int opal_fadump_unregister_fadump(struct fw_dump *fadump_conf)
{
	s64 rc;

	rc = opal_mpipl_update(OPAL_MPIPL_REMOVE_ALL, 0, 0, 0);
	if (rc) {
		pr_err("Failed to un-register - unexpected Error(%lld).\n", rc);
		return -EIO;
	}

	opal_fdm->registered_regions = 0;
	fadump_conf->dump_registered = 0;
	return 0;
}

static int opal_fadump_invalidate_fadump(struct fw_dump *fadump_conf)
{
	s64 rc;

	rc = opal_mpipl_update(OPAL_MPIPL_FREE_PRESERVED_MEMORY, 0, 0, 0);
	if (rc) {
		pr_err("Failed to invalidate - unexpected Error(%lld).\n", rc);
		return -EIO;
	}

	fadump_conf->dump_active = 0;
	opal_fdm_active = NULL;
	return 0;
}

static inline void opal_fadump_set_regval_regnum(struct pt_regs *regs,
						 u32 reg_type, u32 reg_num,
						 u64 reg_val)
{
	if (reg_type == HDAT_FADUMP_REG_TYPE_GPR) {
		if (reg_num < 32)
			regs->gpr[reg_num] = reg_val;
		return;
	}

	switch (reg_num) {
	case SPRN_CTR:
		regs->ctr = reg_val;
		break;
	case SPRN_LR:
		regs->link = reg_val;
		break;
	case SPRN_XER:
		regs->xer = reg_val;
		break;
	case SPRN_DAR:
		regs->dar = reg_val;
		break;
	case SPRN_DSISR:
		regs->dsisr = reg_val;
		break;
	case HDAT_FADUMP_REG_ID_NIP:
		regs->nip = reg_val;
		break;
	case HDAT_FADUMP_REG_ID_MSR:
		regs->msr = reg_val;
		break;
	case HDAT_FADUMP_REG_ID_CCR:
		regs->ccr = reg_val;
		break;
	}
}

static inline void opal_fadump_read_regs(char *bufp, unsigned int regs_cnt,
					 unsigned int reg_entry_size,
					 struct pt_regs *regs)
{
	int i;
	struct hdat_fadump_reg_entry *reg_entry;

	memset(regs, 0, sizeof(struct pt_regs));

	for (i = 0; i < regs_cnt; i++, bufp += reg_entry_size) {
		reg_entry = (struct hdat_fadump_reg_entry *)bufp;
		opal_fadump_set_regval_regnum(regs,
					      be32_to_cpu(reg_entry->reg_type),
					      be32_to_cpu(reg_entry->reg_num),
					      be64_to_cpu(reg_entry->reg_val));
	}
}

static inline bool __init is_thread_core_inactive(u8 core_state)
{
	bool is_inactive = false;

	if (core_state == HDAT_FADUMP_CORE_INACTIVE)
		is_inactive = true;

	return is_inactive;
}

/*
 * Convert CPU state data saved at the time of crash into ELF notes.
 *
 * Each register entry is of 16 bytes, A numerical identifier along with
 * a GPR/SPR flag in the first 8 bytes and the register value in the next
 * 8 bytes. For more details refer to F/W documentation.
 */
static int __init opal_fadump_build_cpu_notes(struct fw_dump *fadump_conf)
{
	u32 num_cpus, *note_buf;
	struct fadump_crash_info_header *fdh = NULL;
	struct hdat_fadump_thread_hdr *thdr;
	unsigned long addr;
	u32 thread_pir;
	char *bufp;
	struct pt_regs regs;
	unsigned int size_of_each_thread;
	unsigned int regs_offset, regs_cnt, reg_esize;
	int i;

	if ((fadump_conf->cpu_state_destination_addr == 0) ||
	    (fadump_conf->cpu_state_entry_size == 0)) {
		pr_err("CPU state data not available for processing!\n");
		return -ENODEV;
	}

	size_of_each_thread = fadump_conf->cpu_state_entry_size;
	num_cpus = (fadump_conf->cpu_state_data_size / size_of_each_thread);

	addr = fadump_conf->cpu_state_destination_addr;
	bufp = __va(addr);

	/*
	 * Offset for register entries, entry size and registers count is
	 * duplicated in every thread header in keeping with HDAT format.
	 * Use these values from the first thread header.
	 */
	thdr = (struct hdat_fadump_thread_hdr *)bufp;
	regs_offset = (offsetof(struct hdat_fadump_thread_hdr, offset) +
		       be32_to_cpu(thdr->offset));
	reg_esize = be32_to_cpu(thdr->esize);
	regs_cnt  = be32_to_cpu(thdr->ecnt);

	/* Allocate buffer to hold cpu crash notes. */
	fadump_conf->cpu_notes_buf_size = num_cpus * sizeof(note_buf_t);
	fadump_conf->cpu_notes_buf_size =
		PAGE_ALIGN(fadump_conf->cpu_notes_buf_size);
	note_buf = fadump_cpu_notes_buf_alloc(fadump_conf->cpu_notes_buf_size);
	if (!note_buf) {
		pr_err("Failed to allocate 0x%lx bytes for cpu notes buffer\n",
		       fadump_conf->cpu_notes_buf_size);
		return -ENOMEM;
	}
	fadump_conf->cpu_notes_buf = __pa(note_buf);

	pr_debug("Allocated buffer for cpu notes of size %ld at %p\n",
		 (num_cpus * sizeof(note_buf_t)), note_buf);

	if (fadump_conf->fadumphdr_addr)
		fdh = __va(fadump_conf->fadumphdr_addr);

	pr_debug("--------CPU State Data------------\n");
	pr_debug("NumCpus     : %u\n", num_cpus);
	pr_debug("\tOffset: %u, Entry size: %u, Cnt: %u\n",
		 regs_offset, reg_esize, regs_cnt);

	for (i = 0; i < num_cpus; i++, bufp += size_of_each_thread) {
		thdr = (struct hdat_fadump_thread_hdr *)bufp;

		thread_pir = be32_to_cpu(thdr->pir);
		pr_debug("%04d) PIR: 0x%x, core state: 0x%02x\n",
			 (i + 1), thread_pir, thdr->core_state);

		/*
		 * Register state data of MAX cores is provided by firmware,
		 * but some of this cores may not be active. So, while
		 * processing register state data, check core state and
		 * skip threads that belong to inactive cores.
		 */
		if (is_thread_core_inactive(thdr->core_state))
			continue;

		/*
		 * If this is kernel initiated crash, crashing_cpu would be set
		 * appropriately and register data of the crashing CPU saved by
		 * crashing kernel. Add this saved register data of crashing CPU
		 * to elf notes and populate the pt_regs for the remaining CPUs
		 * from register state data provided by firmware.
		 */
		if (fdh && (fdh->crashing_cpu == thread_pir)) {
			note_buf = fadump_regs_to_elf_notes(note_buf,
							    &fdh->regs);
			pr_debug("Crashing CPU PIR: 0x%x - R1 : 0x%lx, NIP : 0x%lx\n",
				 fdh->crashing_cpu, fdh->regs.gpr[1],
				 fdh->regs.nip);
			continue;
		}

		opal_fadump_read_regs((bufp + regs_offset), regs_cnt,
				      reg_esize, &regs);

		note_buf = fadump_regs_to_elf_notes(note_buf, &regs);
		pr_debug("CPU PIR: 0x%x - R1 : 0x%lx, NIP : 0x%lx\n",
			 thread_pir, regs.gpr[1], regs.nip);
	}
	final_note(note_buf);

	if (fdh) {
		pr_debug("Updating elfcore header (%llx) with cpu notes\n",
			 fdh->elfcorehdr_addr);
		fadump_update_elfcore_header(fadump_conf,
					     __va(fdh->elfcorehdr_addr));
	}

	return 0;
}

static int __init opal_fadump_process_fadump(struct fw_dump *fadump_conf)
{
	struct fadump_crash_info_header *fdh;
	int rc = 0;

	if (!opal_fdm_active || !opal_cpu_metadata ||
	    !fadump_conf->fadumphdr_addr)
		return -EINVAL;

	/* Validate the fadump crash info header */
	fdh = __va(fadump_conf->fadumphdr_addr);
	if (fdh->magic_number != FADUMP_CRASH_INFO_MAGIC) {
		pr_err("Crash info header is not valid.\n");
		return -EINVAL;
	}

	rc = opal_fadump_build_cpu_notes(fadump_conf);
	if (rc)
		return rc;

	/*
	 * We are done validating dump info and elfcore header is now ready
	 * to be exported. set elfcorehdr_addr so that vmcore module will
	 * export the elfcore header through '/proc/vmcore'.
	 */
	elfcorehdr_addr = fdh->elfcorehdr_addr;

	return rc;
}

static void opal_fadump_region_show(struct fw_dump *fadump_conf,
				    struct seq_file *m)
{
	int i;
	const struct opal_fadump_mem_struct *fdm_ptr;
	u64 dumped_bytes = 0;

	if (fadump_conf->dump_active)
		fdm_ptr = opal_fdm_active;
	else
		fdm_ptr = opal_fdm;

	for (i = 0; i < fdm_ptr->region_cnt; i++) {
		/*
		 * Only regions that are registered for MPIPL
		 * would have dump data.
		 */
		if ((fadump_conf->dump_active) &&
		    (i < fdm_ptr->registered_regions))
			dumped_bytes = fdm_ptr->rgn[i].size;

		seq_printf(m, "DUMP: Src: %#016llx, Dest: %#016llx, ",
			   fdm_ptr->rgn[i].src, fdm_ptr->rgn[i].dest);
		seq_printf(m, "Size: %#llx, Dumped: %#llx bytes\n",
			   fdm_ptr->rgn[i].size, dumped_bytes);
	}

	/* Dump is active. Show reserved area start address. */
	if (fadump_conf->dump_active) {
		seq_printf(m, "\nMemory above %#016lx is reserved for saving crash dump\n",
			   fadump_conf->reserve_dump_area_start);
	}
}

static void opal_fadump_trigger(struct fadump_crash_info_header *fdh,
				const char *msg)
{
	int rc;

	/*
	 * Unlike on pSeries platform, logical CPU number is not provided
	 * with architected register state data. So, store the crashing
	 * CPU's PIR instead to plug the appropriate register data for
	 * crashing CPU in the vmcore file.
	 */
	fdh->crashing_cpu = (u32)mfspr(SPRN_PIR);

	rc = opal_cec_reboot2(OPAL_REBOOT_MPIPL, msg);
	if (rc == OPAL_UNSUPPORTED) {
		pr_emerg("Reboot type %d not supported.\n",
			 OPAL_REBOOT_MPIPL);
	} else if (rc == OPAL_HARDWARE)
		pr_emerg("No backend support for MPIPL!\n");
}

static struct fadump_ops opal_fadump_ops = {
	.init_fadump_mem_struct		= opal_fadump_init_mem_struct,
	.get_kernel_metadata_size	= opal_fadump_get_kernel_metadata_size,
	.setup_kernel_metadata		= opal_fadump_setup_kernel_metadata,
	.register_fadump		= opal_fadump_register_fadump,
	.unregister_fadump		= opal_fadump_unregister_fadump,
	.invalidate_fadump		= opal_fadump_invalidate_fadump,
	.process_fadump			= opal_fadump_process_fadump,
	.fadump_region_show		= opal_fadump_region_show,
	.fadump_trigger			= opal_fadump_trigger,
};

int __init opal_fadump_dt_scan(struct fw_dump *fadump_conf, ulong node)
{
	unsigned long dn;
	const __be32 *prop;

	/*
	 * Check if Firmware-Assisted Dump is supported. if yes, check
	 * if dump has been initiated on last reboot.
	 */
	dn = of_get_flat_dt_subnode_by_name(node, "dump");
	if (dn == -FDT_ERR_NOTFOUND) {
		pr_debug("FADump support is missing!\n");
		return 1;
	}

	if (!of_flat_dt_is_compatible(dn, "ibm,opal-dump")) {
		pr_err("Support missing for this f/w version!\n");
		return 1;
	}

	fadump_conf->ops		= &opal_fadump_ops;
	fadump_conf->fadump_platform	= FADUMP_PLATFORM_POWERNV;
	fadump_conf->fadump_supported	= 1;

	/*
	 * Firmware currently supports only 32-bit value for size,
	 * align it to pagesize.
	 */
	fadump_conf->max_copy_size = _ALIGN_DOWN(U32_MAX, PAGE_SIZE);

	/*
	 * Check if dump has been initiated on last reboot.
	 */
	prop = of_get_flat_dt_prop(dn, "mpipl-boot", NULL);
	if (prop) {
		u64 addr = 0;
		s64 ret;
		const struct opal_fadump_mem_struct *r_opal_fdm_active;
		const struct opal_mpipl_fadump *r_opal_cpu_metadata;

		ret = opal_mpipl_query_tag(OPAL_MPIPL_TAG_KERNEL, &addr);
		if ((ret != OPAL_SUCCESS) || !addr) {
			pr_err("Failed to get Kernel metadata (%lld)\n", ret);
			return 1;
		}

		addr = be64_to_cpu(addr);
		pr_debug("Kernel metadata addr: %llx\n", addr);

		opal_fdm_active = __va(addr);
		r_opal_fdm_active = (void *)addr;
		if (r_opal_fdm_active->version != OPAL_FADUMP_VERSION) {
			pr_err("FADump active but version (%u) unsupported!\n",
			       r_opal_fdm_active->version);
			return 1;
		}

		/* Kernel regions not registered with f/w  for MPIPL */
		if (r_opal_fdm_active->registered_regions == 0) {
			opal_fdm_active = NULL;
			return 1;
		}

		ret = opal_mpipl_query_tag(OPAL_MPIPL_TAG_CPU, &addr);
		if ((ret != OPAL_SUCCESS) || !addr) {
			pr_err("Failed to get CPU metadata (%lld)\n", ret);
			return 1;
		}

		addr = be64_to_cpu(addr);
		pr_debug("CPU metadata addr: %llx\n", addr);

		opal_cpu_metadata = __va(addr);
		r_opal_cpu_metadata = (void *)addr;
		fadump_conf->cpu_state_data_version =
			be32_to_cpu(r_opal_cpu_metadata->cpu_data_version);
		if (fadump_conf->cpu_state_data_version !=
		    HDAT_FADUMP_CPU_DATA_VERSION) {
			pr_err("CPU data format version (%lu) mismatch!\n",
			       fadump_conf->cpu_state_data_version);
			return 1;
		}
		fadump_conf->cpu_state_entry_size =
			be32_to_cpu(r_opal_cpu_metadata->cpu_data_size);
		fadump_conf->cpu_state_destination_addr =
			be64_to_cpu(r_opal_cpu_metadata->region[0].dest);
		fadump_conf->cpu_state_data_size =
			be64_to_cpu(r_opal_cpu_metadata->region[0].size);

		pr_info("Firmware-assisted dump is active.\n");
		fadump_conf->dump_active = 1;
		opal_fadump_get_config(fadump_conf, r_opal_fdm_active);
	}

	return 1;
}
