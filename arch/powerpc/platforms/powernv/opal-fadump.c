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

#include <asm/page.h>
#include <asm/opal.h>

#include "../../kernel/fadump-common.h"
#include "opal-fadump.h"

static struct opal_fadump_mem_struct *opal_fdm;

static ulong opal_fadump_init_mem_struct(struct fw_dump *fadump_conf)
{
	ulong addr = fadump_conf->reserve_dump_area_start;

	opal_fdm = __va(fadump_conf->kernel_metadata);
	opal_fdm->version = OPAL_FADUMP_VERSION;
	opal_fdm->region_cnt = 1;
	opal_fdm->registered_regions = 0;
	opal_fdm->rgn[0].src	= RMA_START;
	opal_fdm->rgn[0].dest	= addr;
	opal_fdm->rgn[0].size	= fadump_conf->boot_memory_size;
	addr += fadump_conf->boot_memory_size;

	/*
	 * Kernel metadata is passed to f/w and retrieved in capture kerenl.
	 * So, use it to save fadump header address instead of calculating it.
	 */
	opal_fdm->fadumphdr_addr = (opal_fdm->rgn[0].dest +
				    fadump_conf->boot_memory_size);

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
	return -EIO;
}

static int opal_fadump_unregister_fadump(struct fw_dump *fadump_conf)
{
	return -EIO;
}

static int opal_fadump_invalidate_fadump(struct fw_dump *fadump_conf)
{
	return -EIO;
}

static int __init opal_fadump_process_fadump(struct fw_dump *fadump_conf)
{
	return -EINVAL;
}

static void opal_fadump_region_show(struct fw_dump *fadump_conf,
				    struct seq_file *m)
{
	int i;
	const struct opal_fadump_mem_struct *fdm_ptr = opal_fdm;
	u64 dumped_bytes = 0;

	for (i = 0; i < fdm_ptr->region_cnt; i++) {
		seq_printf(m, "DUMP: Src: %#016llx, Dest: %#016llx, ",
			   fdm_ptr->rgn[i].src, fdm_ptr->rgn[i].dest);
		seq_printf(m, "Size: %#llx, Dumped: %#llx bytes\n",
			   fdm_ptr->rgn[i].size, dumped_bytes);
	}
}

static void opal_fadump_trigger(struct fadump_crash_info_header *fdh,
				const char *msg)
{
	int rc;

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

	return 1;
}
