/*
 * Bits from:
 *
 * Copyright (c) 2015, Christoph Hellwig.
 * Copyright (c) 2015, Intel Corporation.
 */

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

/* device specific setup */
struct contutto_device {
	struct nvdimm_bus *bus;
	struct nvdimm_bus_descriptor nd_desc;
	phys_addr_t magic_page_phys;
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
	struct resource *flush_res = NULL;
	struct device *dev = &pdev->dev;
	struct contutto_device *ct;
	struct nvdimm *nvdimm;
	int i;

	if (!pdev->num_resources ) {
		dev_err(&pdev->dev, "Missing resources!\n");
		return -ENXIO;
	} else if (pdev->num_resources > 1) {
		/* the last resouce is always the cache-inhibited region */
		flush_res = &pdev->resource[pdev->num_resources - 1];
		dev_dbg(dev, "flush res: %pr\n", flush_res);
	}

	ct = kzalloc(sizeof(*ct), GFP_KERNEL);
	if (!ct)
		return -ENOMEM;

	ct->nd_desc.attr_groups = ct_pmem_attribute_groups;
	ct->nd_desc.provider_name = "contutto";
	ct->bus = nvdimm_bus_register(dev, &ct->nd_desc);
	if (!ct->bus)
		goto err;

	platform_set_drvdata(pdev, ct);

	nvdimm = nvdimm_create(ct->bus, ct, NULL, 0, 0, 1, flush_res);

	if (!nvdimm)
		goto err;

	/* Add memory regions now that we have the infrastructure */
	for (i = 0; i < pdev->num_resources - 1; i++) {
		struct resource *p = &pdev->resource[i];
		struct nd_mapping_desc nd_mapping;
		struct nd_region_desc ndr_desc;

		memset(&nd_mapping, 0, sizeof(nd_mapping));
		nd_mapping.nvdimm = nvdimm;
		nd_mapping.start = p->start;
		nd_mapping.size  = p->end + 1 - p->start;

		dev_dbg(dev, " %d: %pr\n", i, &pdev->resource[i]);

		memset(&ndr_desc, 0, sizeof(ndr_desc));
		ndr_desc.res = p;
		ndr_desc.attr_groups = ct_pmem_region_attribute_groups;
		ndr_desc.mapping = &nd_mapping;
		ndr_desc.num_mappings = 1;

		/*
		 * FIXME: NUMA association
		 */
		//ndr_desc.numa_node = pdev->dev.numa_node;

		/*
		 * Setting this flag indicates the NVDIMM bus should generate a
		 * page structs for this region.
		 */
		set_bit(ND_REGION_PAGEMAP, &ndr_desc.flags);

		if (!nvdimm_pmem_region_create(ct->bus, &ndr_desc))
			goto err;
	}

	return 0;

err:
	nvdimm_bus_unregister(ct->bus); /* XXX: cleanup? */
	kfree(ct);
	dev_err(dev, "Failed to register contutto memory ranges\n");

	return -ENXIO;
}

static int ct_pmem_remove(struct platform_device *pdev)
{
	struct contutto_device *ct = platform_get_drvdata(pdev);

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
		.name = "contutto",
		.owner = THIS_MODULE,
		.of_match_table = ct_pmem_match,
	},
};

static int con_mmap_magic(struct file *f, struct kobject *kobj,
		struct bin_attribute *attr, struct vm_area_struct *vma)
{
	struct platform_device *pdev;
	struct contutto_device *ct;
	struct device *dev;

	dev = container_of(kobj->parent, struct device, kobj);
	pdev = container_of(dev, struct platform_device, dev);
	ct = platform_get_drvdata(pdev);

	/*
	 * magic page must be mapped read-only, the card will ensures
	 * that cache inhibited loads return garbage, but writes will
	 * go through.
	 */
	if (vma->vm_flags & (VM_WRITE | VM_EXEC))
		return -EPERM;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return vm_iomap_memory(vma, ct->magic_page_phys, PAGE_SIZE);
}

module_platform_driver(ct_pmem_driver);
MODULE_DEVICE_TABLE(of, ct_pmem_match);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("IBM Corporation");
