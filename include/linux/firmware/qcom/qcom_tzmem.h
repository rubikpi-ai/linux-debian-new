/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023-2024 Linaro Ltd.
 */

#ifndef __QCOM_TZMEM_H
#define __QCOM_TZMEM_H

#include <linux/cleanup.h>
#include <linux/gfp.h>
#include <linux/types.h>

struct device;
struct qcom_tzmem_pool;

/**
 * enum qcom_tzmem_policy - Policy for pool growth.
 */
enum qcom_tzmem_policy {
	/**< Static pool, never grow above initial size. */
	QCOM_TZMEM_POLICY_STATIC = 1,
	/**< When out of memory, add increment * current size of memory. */
	QCOM_TZMEM_POLICY_MULTIPLIER,
	/**< When out of memory add as much as is needed until max_size. */
	QCOM_TZMEM_POLICY_ON_DEMAND,
};

/**
 * struct qcom_tzmem_pool_config - TZ memory pool configuration.
 * @initial_size: Number of bytes to allocate for the pool during its creation.
 * @policy: Pool size growth policy.
 * @increment: Used with policies that allow pool growth.
 * @max_size: Size above which the pool will never grow.
 */
struct qcom_tzmem_pool_config {
	size_t initial_size;
	enum qcom_tzmem_policy policy;
	size_t increment;
	size_t max_size;
};

struct qcom_tzmem_area {
	struct list_head list;
	void *vaddr;
	dma_addr_t paddr;
	size_t size;
	void *priv;
};

struct qcom_tzmem_pool *
qcom_tzmem_pool_new(const struct qcom_tzmem_pool_config *config);
void qcom_tzmem_pool_free(struct qcom_tzmem_pool *pool);
struct qcom_tzmem_pool *
devm_qcom_tzmem_pool_new(struct device *dev,
			 const struct qcom_tzmem_pool_config *config);

void *qcom_tzmem_alloc(struct qcom_tzmem_pool *pool, size_t size, gfp_t gfp);
void qcom_tzmem_free(void *ptr);

#if IS_ENABLED(CONFIG_QCOM_TZMEM_MODE_SHMBRIDGE)
int qcom_tzmem_init_area(struct qcom_tzmem_area *area);
void qcom_tzmem_cleanup_area(struct qcom_tzmem_area *area);
#else
static int qcom_tzmem_init_area(struct qcom_tzmem_area *area)
{
	return 0;
}

static void qcom_tzmem_cleanup_area(struct qcom_tzmem_area *area)
{

}
#endif
DEFINE_FREE(qcom_tzmem, void *, if (_T) qcom_tzmem_free(_T))

phys_addr_t qcom_tzmem_to_phys(void *ptr);

int32_t qcom_tzmem_deregister(uint64_t handle);
int32_t qcom_tzmem_register(
		phys_addr_t paddr,
		size_t size,
		uint32_t *ns_vmid_list,
		uint32_t *ns_vm_perm_list,
		uint32_t ns_vmid_num,
		uint32_t tz_perm,
		uint64_t *handle);

#endif /* __QCOM_TZMEM */
