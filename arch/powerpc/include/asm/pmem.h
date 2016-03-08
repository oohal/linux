/*
 * Copyright(c) 2017 IBM Corporation. All rights reserved.
 *
 * Based on the x86 version.
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
#ifndef __ASM_POWERPC_PMEM_H__
#define __ASM_POWERPC_PMEM_H__

#include <linux/uio.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>

/*
 * See include/linux/pmem.h for API documentation
 *
 * PPC specific notes:
 *
 * 1. PPC has no non-temporal (cache bypassing) stores so we're stuck with
 *    doing cache writebacks.
 *
 * 2. DCBST is a suggestion. DCBF will force a writeback.
 *
 */

static inline void arch_wb_cache_pmem(void *addr, size_t size)
{
	unsigned long iaddr = (unsigned long) addr;

	/* NB: contains a barrier */
	flush_inval_dcache_range(iaddr, iaddr + size);
}

/* invalidate and writeback are functionally identical */
#define arch_invalidate_pmem arch_wb_cache_pmem

static inline void arch_memcpy_to_pmem(void *dst, const void *src, size_t n)
{
	int unwritten;

	/*
	 * We are copying between two kernel buffers, if
	 * __copy_from_user_inatomic_nocache() returns an error (page
	 * fault) we would have already reported a general protection fault
	 * before the WARN+BUG.
	 *
	 * XXX: replace this with a hand-rolled memcpy+dcbf
	 */
	unwritten = __copy_from_user_inatomic(dst, (void __user *) src, n);
	if (WARN(unwritten, "%s: fault copying %p <- %p unwritten: %d\n",
				__func__, dst, src, unwritten))
		BUG();

	arch_wb_cache_pmem(dst, n);
}

static inline int arch_memcpy_from_pmem(void *dst, const void *src, size_t n)
{
	/*
	 * TODO: We should have most of the infrastructure for MCE handling
	 *       but it needs to be made slightly smarter.
	 */
	memcpy(dst, src, n);
	return 0;
}

static inline size_t arch_copy_from_iter_pmem(void *addr, size_t bytes,
		struct iov_iter *i)
{
	size_t len;

	/* XXX: under what conditions would this return len < size? */
	len = copy_from_iter(addr, bytes, i);
	arch_wb_cache_pmem(addr, bytes - len);

	return len;
}

static inline void arch_clear_pmem(void *addr, size_t size)
{
	void *start = addr;

	/*
	 * XXX: A hand rolled dcbz+dcbf loop would probably be better.
	 */

	if (((uintptr_t) addr & ~PAGE_MASK) == 0) {
		while (size >= PAGE_SIZE) {
			clear_page(addr);
			addr += PAGE_SIZE;
			size -= PAGE_SIZE;
		}
	}

	if (size)
		memset(addr, 0, size);

	arch_wb_cache_pmem(start, size);
}

#endif /* __ASM_POWERPC_PMEM_H__ */
