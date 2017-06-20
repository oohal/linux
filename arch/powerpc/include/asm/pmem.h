/*
 * Copyright(c) 2017 IBM Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#ifndef __ASM_PMEM_H__
#define __ASM_PMEM_H__

#include <linux/string.h>
#include <asm/cacheflush.h>

#ifdef CONFIG_ARCH_HAS_PMEM_API
static inline void arch_wb_cache_pmem(void *addr, size_t size)
{
	unsigned long start = (unsigned long) addr;
	flush_inval_dcache_range(start, start + size);
}

static inline void arch_invalidate_pmem(void *addr, size_t size)
{
	unsigned long start = (unsigned long) addr;
	flush_inval_dcache_range(start, start + size);
}

static inline void *memcpy_flushcache(void *dest, const void *src, size_t size)
{
	unsigned long start = (unsigned long) dest;

	memcpy(dest, src, size);
	flush_inval_dcache_range(start, start + size);

	return dest;
}
#endif /* CONFIG_ARCH_HAS_PMEM_API */
#endif /* __ASM_PMEM_H__ */
