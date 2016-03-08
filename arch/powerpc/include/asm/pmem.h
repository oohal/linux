/*
 * Copyright(c) 2015 IBM Corporation. All rights reserved.
 * Copyright(c) 2015 Intel Corporation. All rights reserved.
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
 * PPC specific notes:
 *
 * 1. PPC has no non-temporal (cache bypassing) stores so all stores to pmem
 *    go via the cache. Any functions that write to pmem needs to do the correct
 *    cache writebacks.
 *
 * 2. Cache writeback/invalidate operations are treated as loads.
 *
 * 3. A full barrier (sync instruction) will ensure that cache invalidate and
 *    writeback operations have completed.
 *
 * 4. WPQ flushes are triggered using MMIO operations. These provide the full
 *    barrier required to complete any pending cache writebacks in addition
 *    to flushing the WPQ queue.
 */

static inline void arch_wb_cache_pmem(void *addr, size_t size)
{
	unsigned long iaddr = (unsigned long) addr;
	flush_dcache_range_nosync(iaddr, iaddr + size);
}

/**
 * arch_memcpy_to_pmem - copy data to persistent memory
 * @dst: destination buffer for the copy
 * @src: source buffer for the copy
 * @n: length of the copy in bytes
 *
 * Copy data to persistent memory media and writeback. There will be a
 * subsequent flush operation to ensure any pending cache writeback ops
 * are done and flushed.
 */
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
	/* TODO: MCE handling */
	memcpy(dst, src, n);
	return 0;
}

/**
 * arch_copy_from_iter_pmem - copy data from an iterator to PMEM
 * @addr:	PMEM destination address
 * @bytes:	number of bytes to copy
 * @i:		iterator with source data
 *
 * Copy data from the iterator 'i' to the PMEM buffer starting at 'addr'.
 * This function requires explicit ordering with an arch_wmb_pmem() call.
 */
static inline size_t arch_copy_from_iter_pmem(void *addr, size_t bytes,
		struct iov_iter *i)
{
	size_t len;

	len = copy_from_iter(addr, bytes, i);
	arch_wb_cache_pmem(addr, bytes);

	return len;
}

/**
 * arch_clear_pmem - zero a PMEM memory range
 * @addr:	virtual start address
 * @size:	number of bytes to zero
 *
 * Write zeros into the memory range starting at 'addr' for 'size' bytes.
 * This function requires explicit ordering with an arch_wmb_pmem() call.
 */
static inline void arch_clear_pmem(void *addr, size_t size)
{
	uintptr_t iaddr = (uintptr_t ) addr;

	if (size == PAGE_SIZE && (iaddr & ~PAGE_MASK) == 0)
		clear_page(addr);
	else
		memset(addr, 0, size);

	arch_wb_cache_pmem(addr, size);
}

static inline void arch_invalidate_pmem(void *addr, size_t size)
{
	unsigned long iaddr = (unsigned long) addr;
	flush_dcache_range(iaddr, iaddr + size);
}

#endif /* __ASM_POWERPC_PMEM_H__ */
