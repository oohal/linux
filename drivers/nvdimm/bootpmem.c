// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2015, Christoph Hellwig.
 * Copyright (c) 2015, Intel Corporation.
 */

#define pr_fmt(fmt) "bootpmem: " fmt

#include <linux/libnvdimm.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/mmzone.h>
#include <linux/cpu.h>
#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/ioport.h>

#include "nd.h"
#include "pfn.h"

#ifdef CONFIG_BOOTPMEM

#ifdef CONFIG_SPARSEMEM
#define BOOTPMEM_ALIGN max(PFN_DEFAULT_ALIGNMENT, 1ul << PA_SECTION_SHIFT)
#else
#define BOOTPMEM_ALIGN PFN_DEFAULT_ALIGNMENT
#endif

static int reserve_bootpmem(unsigned long size, int nid)
{
	struct resource *res;
	uint64_t align;
	void *alloc;

	alloc = memblock_virt_alloc_try_nid_nopanic(size, BOOTPMEM_ALIGN,
						    0, 0, nid);
	if (!alloc)
		return 1;

	res = memblock_virt_alloc_try_nid_nopanic(
			sizeof(*res), 0, 0, ~0ul, NUMA_NO_NODE);
	if (!res)
		goto err1;

	memset(res, 0, sizeof(*res));
	res->start = __pa(alloc);
	res->end = __pa(alloc) + size - 1;
	res->name = "bootpmem";
	res->flags = IORESOURCE_MEM;
	res->desc = IORES_DESC_PERSISTENT_MEMORY_LEGACY;

	/*
	 * Remove this range from the memblocks so we don't end up
	 * with a "System RAM" resource that overlaps it later
	 * on.
	 */
	if (memblock_remove(__pa(alloc), size))
		goto err2;

	if (insert_resource(&iomem_resource, res))
		goto err3;

	pr_err("reserved: %pR\n", res);

	return 0;

err3:	memblock_add(__pa(alloc), size);
err2:	memblock_free(virt_to_phys(res), sizeof(*res));
err1:	memblock_free(virt_to_phys(alloc), size);
	return 1;
}

/*
 * bootpmem=ss[KMG] or ss[KMG]@nid
 *
 * This is similar to the memremap=offset[KMG]!size[KMG] paramater
 * for adding a legacy pmem range to the e820 map on x86, but it's
 * platform agnostic.
 *
 * e.g. bootpmem=16G,16G,32G@8 allocates two 16G pmem regions on any node
 * 	and one 32G region on node 8.
 */
int __init parse_bootpmem(char *p)
{
	unsigned long long size;
	int nid;

	while (*p) {
		pr_err("p = '%s'\n", p);

		size = memparse(p, &p);
		if (!size)
			continue;

		if (*p != '@' || kstrtoint(p + 1, 10, &nid))
			nid = NUMA_NO_NODE;

		if (reserve_bootpmem(size, nid))
			pr_err("Unable to reserve %llu bytes on node %d",
					size, nid);

		p = strchr(p, ',');
		if (!p)
			break;
		p++;
	}

	return 0;

}
early_param("bootpmem", parse_bootpmem);

#endif

static int found(struct resource *res, void *data)
{
	return 1;
}

static __init int register_e820_pmem(void)
{
	struct platform_device *pdev;
	int rc;

	rc = walk_iomem_res_desc(IORES_DESC_PERSISTENT_MEMORY_LEGACY,
				 IORESOURCE_MEM, 0, -1, NULL, found);
	if (rc <= 0)
		return 0;

	/*
	 * See drivers/nvdimm/e820.c for the implementation, this is
	 * simply here to trigger the module to load on demand.
	 */
	pdev = platform_device_alloc("e820_pmem", -1);
	return platform_device_add(pdev);
}
device_initcall(register_e820_pmem);
