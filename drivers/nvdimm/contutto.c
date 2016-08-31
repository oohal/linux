/*
 * Copyright 2015, IBM Corp
 *
 * Bits from:
 *
 * Copyright (c) 2015, Christoph Hellwig.
 * Copyright (c) 2015, Intel Corporation.
 */

#define DEBUG

#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/libnvdimm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/sysfs.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/pmem.h>
#include <asm/tlbflush.h>

static int con_mmap_magic(struct file *f, struct kobject *kobj,
		struct bin_attribute *attr, struct vm_area_struct *vma);

static struct bin_attribute contutto_magic_file = {
	.attr = {.name = "magic_page", .mode = 0444},
	.size = PAGE_SIZE,
	.mmap = con_mmap_magic,
};

static struct bin_attribute *magic_page_attributes[] = {
        &contutto_magic_file,
        NULL,
};

static const struct attribute_group magic_page_attribute_group = {
        .bin_attrs = magic_page_attributes,
};

static const struct attribute_group *ct_pmem_attribute_groups[] = {
	&nvdimm_bus_attribute_group,
	&magic_page_attribute_group,
	NULL,
};

static const struct attribute_group *ct_pmem_region_attribute_groups[] = {
	&nd_region_attribute_group,
	&nd_device_attribute_group,
	NULL,
};

/* setup_magic_page - maps the magic page
 *
 * This function assumes the magic page is device memory. If the page is
 * "normal" system memory it memory it will be mapped in the kernel linear
 * mapping and ioremap()ing it will cause a machine check due to incompatible
 * caching attributes.
 */

static void *setup_magic_page(struct device *dev, phys_addr_t phys)
{
	char *p;
	int i;

	/*
	 * ioremap_wc gives us an uncached and unguarded mapping. There's no
	 * need for a guarded mapping in this case since appropriate memory
	 * barriers are provided by the kernel/userspace library.
	 */
	void *magic_addr = devm_ioremap(dev, phys, PAGE_SIZE);

	pr_info("CONTUTTO: magic page mapped (phys 0x%.16llx, virt %p)\n",
		phys, magic_addr);

	/*
	 * Zero the magic page while we're here. Cache-inhibited loads from the
	 * contutto card should always return garbage, but lets be paranoid
	 * about leaking data.
	 */
	for (p = magic_addr, i = 0; i < PAGE_SIZE; i++)
		p[i] = i & 0xff;

	pr_info("CONTUTTO: cleared magic page\n");

	return magic_addr;
}

/* device specific setup */

struct contutto_device {
	struct nvdimm_bus *bus;
	struct nvdimm_bus_descriptor nd_desc;
	void *magic_page_virt;		/* the kernel magic page mapping */
	phys_addr_t magic_page_phys;	/* magic page physical addr      */
};

/*
 * TODO: This should probe nvdimm devices into an existing bus rather than
 *       creating a new bus per device. The bus-per-device thing is only
 *       required because of how flush pages are resolved, but we should
 *       be able to do this more sensibly since the region should contain
 *       a link to the backing nvdimm.
 */

static int ct_pmem_probe(struct platform_device *pdev)
{
	struct contutto_device *ct;
	struct device *dev = &pdev->dev;
	struct resource *flush_res;
	struct nvdimm *nvdimm;
	int res_count;
	int i;

	/*
	 * For any Contutto card we expect two resources. A single page
	 * of magic-page area and any other ranges covered by the card.
	 */

	dev_info(&pdev->dev, "Found NVDIMM!\n");
	res_count = pdev->num_resources;

	for (i = 0; i < pdev->num_resources; i++) {
		dev_info(&pdev->dev, " %d: %pr\n", i, &pdev->resource[i]);
	}

	if (pdev->num_resources < 2) {
		dev_err(&pdev->dev, "Missing resources!\n");
		return -ENXIO;
	}

	flush_res = &pdev->resource[res_count - 1];

	/*
	 * Register, etc
	 */

	ct = kzalloc(sizeof(*ct), GFP_KERNEL);
	if (!ct)
		return -ENOMEM;

#if 0
	/* XXX: disabled since the NVDIMM core will setup the required mappings
	 * for the CI load
	 */

	/* setup the magic page, this is passed to the region driver
	 * via nd_desc->provider_data */
	ct->magic_page_phys = flush_res->start;

	ct->magic_page_virt = setup_magic_page(dev, ct->magic_page_phys);
	if (!ct->magic_page_virt)
		goto err;
#endif
	ct->nd_desc.attr_groups = ct_pmem_attribute_groups;
	ct->nd_desc.provider_name = "contutto";

	ct->bus = nvdimm_bus_register(dev, &ct->nd_desc);
	if (!ct->bus)
		goto err;

	platform_set_drvdata(pdev, ct);

/*
struct nvdimm *nvdimm_create(struct nvdimm_bus *nvdimm_bus, void *provider_data,
348                 const struct attribute_group **groups, unsigned long flags,
349                 unsigned long cmd_mask, int num_flush,
350                 struct resource *flush_wpq)
351 {
*/
	/*
	 * Register the backing nvdimm device.
	 *
	 * FIXME: I think we do want some kind of attribute group here, but I'm
	 * not sure what/which
	 */
	nvdimm = nvdimm_create(ct->bus, ct,
		NULL, 0,
		0, 1,
		flush_res);
	pr_debug("flush res: %p = %pr\n", flush_res, flush_res);

	/* XXX: Fix this so we return ENOMEM */
	if (!nvdimm)
		goto err;
	pr_err("created nvdimm\n");

	/* Add memory regions now that we have the infrastructure */
	for (i = 0; i < pdev->num_resources - 1; i++) {
		struct resource *p = &pdev->resource[i];
		struct nd_region_desc ndr_desc;
		struct nd_mapping_desc nd_mapping;


		if (!(p->flags & IORESOURCE_MEM))
			continue;

		memset(&nd_mapping, 0, sizeof(nd_mapping));
		nd_mapping.nvdimm = nvdimm;
		nd_mapping.start = p->start;
		nd_mapping.size  = p->end + 1 - p->start;

		dev_info(&pdev->dev, " %d: %pr\n", i, &pdev->resource[i]);
	       	pr_info("res: start %llx end %llx\n", p->start, p->end);	/* maybe? */

		memset(&ndr_desc, 0, sizeof(ndr_desc));
		ndr_desc.res = p;
		ndr_desc.attr_groups = ct_pmem_region_attribute_groups;
//		ndr_desc.provider_data = ct->magic_page_virt;
		ndr_desc.mapping = &nd_mapping;
		ndr_desc.num_mappings = 1;

		/*
		 * FIXME: We should export the associativities from HDAT
		 * so we get proper numa association. We need to add a DT
		 * property for this first.
		 */
		//ndr_desc.numa_node = pdev->dev.numa_node;

		/*
		 * Setting this flag indicates the NVDIMM bus should generate a
		 * page structs for this region.
		 */
		set_bit(ND_REGION_PAGEMAP, &ndr_desc.flags);

		if (!nvdimm_pmem_region_create(ct->bus, &ndr_desc))
			goto err;

		pr_err("registered\n");
	}

	return 0;

err:
	/* unmapping the magic page is taken care of by the device destructor */
//	nvdimm_destory(nvdimm); /* what's the correct method for this? */

	nvdimm_bus_unregister(ct->bus);
	kfree(ct);
	dev_err(dev, "Failed to register persistent memory ranges\n");
	return -ENXIO;
}

static int ct_pmem_remove(struct platform_device *pdev)
{
	struct contutto_device *ct = platform_get_drvdata(pdev);

	/*
	 * most of our de-init is handled for us via driver resources clean up.
	 *
	 * XXX: When this is called, what happens to the userspace mapped pages?
	 *      Does mmap()ing the sysfs file increase the module's refcount?
	 *      hope so...
	 */

	nvdimm_bus_unregister(ct->bus);
	kfree(ct);

	return 0;
}


static const struct of_device_id ct_pmem_match[] = {
	{ .compatible = "ibm,contutto-nvmem" },
	{ },
};

static struct platform_driver ct_pmem_driver = {
	.probe = ct_pmem_probe,
	.remove = ct_pmem_remove,
	.driver = {
		.name = "contutto-pmem",
		.owner = THIS_MODULE,
		.of_match_table = ct_pmem_match,
	},
};

static int con_mmap_magic(struct file *f, struct kobject *kobj,
		struct bin_attribute *attr, struct vm_area_struct *vma)
{
	struct device *dev = container_of(kobj->parent, struct device, kobj);
	struct platform_device *pdev =
		container_of(dev, struct platform_device, dev);
	struct contutto_device *ct   = platform_get_drvdata(pdev);

	/*
	 * magic page must be mapped read-only, the contutto card will
	 * ensure that cache inhibited loads return garbage, but writes
	 * will go through.
	 *
	 * FIXME: is this test even necessary? might be handled somewhere higher
	 *        up the mmap call chain.
	 */
	if (vma->vm_flags & (VM_WRITE | VM_EXEC)) {
		return -EPERM;
	}

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return vm_iomap_memory(vma, ct->magic_page_phys, PAGE_SIZE);
}

module_platform_driver(ct_pmem_driver);
MODULE_DEVICE_TABLE(of, ct_pmem_match);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("IBM Corporation");
