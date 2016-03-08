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
 * Implements:
 *
 *	arch_memcpy_to_pmem()
 *	arch_memcpy_from_pmem()
 *	arch_copy_from_iter_pmem()
 *	arch_clear_pmem()
 *	arch_wb_cache_pmem()
 *	arch_invalidate_pmem()
 *
 * PPC specific notes:
 *
 * 1. PPC has no non-temporal (cache bypassing) stores so all stores to pmem
 *    go via the cache. Any functions that write to pmem needs to do the correct
 *    cache writebacks.
 *
 * 2. Cache writeback/invalidate operations are treated as loads for ordering
 *    purposes. This is annoying since it requires that we use a full sync
 *    rather than a lwsync.
 *
 * 3. A full barrier (sync instruction) will ensure that cache invalidate and
 *    writeback operations have completed.
 *
 * 4. WPQ flushes are triggered using MMIO operations. These provide the full
 *    barrier required to complete any pending cache writebacks in addition
 *    to flushing the WPQ queue.
 */

/* invalidate and writeback are the same currently */
#define arch_invalidate_pmem arch_wb_cache_pmem

static inline void arch_wb_cache_pmem(void *addr, size_t size)
{
	unsigned long iaddr = (unsigned long) addr;
	flush_dcache_range(iaddr, iaddr + size);
}

static inline void arch_memcpy_to_pmem(void *dst, const void *src, size_t n)
{
	int unwritten;

	/*
	 * We are copying between two kernel buffers, if
	 * __copy_from_user_inatomic_nocache() returns an error (page
	 * fault) we would have already reported a general protection fault
	 * before the WARN+BUG.
	 */
	unwritten = __copy_from_user_inatomic(dst, (void __user *) src, n);
	if (WARN(unwritten, "%s: fault copying %p <- %p unwritten: %d\n",
				__func__, dst, src, unwritten))
		BUG();

	/*
	 * NB: Writes to pmem may not be in the WPQ when this function returns.
	 * A full barrier is required first.
	 *
	 * FIXME: We should get better performance for larger transfers by doing
	 * per-cacheline flushes inside the memcpy loop. It's a bit of a mess
	 * though...
	 */
	arch_wb_cache_pmem(dst, n);
}

static inline int arch_memcpy_from_pmem(void *dst, const void *src, size_t n)
{
	/*
	 * TODO: MCE handling. We should have most of the infrastructure
	 * for it already.
	 */
	memcpy(dst, src, n);
	return 0;
}

static inline size_t arch_copy_from_iter_pmem(void *addr, size_t bytes,
		struct iov_iter *i)
{
	size_t len;

	len = copy_from_iter(addr, bytes, i);
	arch_wb_cache_pmem(addr, bytes - len);

	return len;
}

static inline void arch_clear_pmem(void *addr, size_t size)
{
	uintptr_t iaddr = (uintptr_t ) addr;

	if (size == PAGE_SIZE && (iaddr & ~PAGE_MASK) == 0)
		clear_page(addr);
	else
		memset(addr, 0, size);

	arch_wb_cache_pmem(addr, size);
}


#endif /* __ASM_POWERPC_PMEM_H__ */
