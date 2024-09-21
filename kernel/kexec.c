// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec.c - kexec_load system call
 * Copyright (C) 2002-2004 Eric Biederman <ebiederm@xmission.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/kexec.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "kexec_internal.h"

/* Kernel image allocation and initialization */
static int kimage_alloc_init(struct kimage **rimage, unsigned long entry,
			     unsigned long nr_segments,
			     struct kexec_segment *segments,
			     unsigned long flags)
{
	int ret;
	struct kimage *image;
	bool kexec_on_panic = flags & KEXEC_ON_CRASH;

#ifdef CONFIG_CRASH_DUMP
	/* Ensure valid entry point for crash kernel */
	if (kexec_on_panic && 
		(entry < phys_to_boot_phys(crashk_res.start) || entry > phys_to_boot_phys(crashk_res.end)))
		return -EADDRNOTAVAIL;
#endif

	/* Allocate kernel image structure */
	image = do_kimage_alloc_init();
	if (!image)
		return -ENOMEM;

	image->start = entry;
	image->nr_segments = nr_segments;
	memcpy(image->segment, segments, nr_segments * sizeof(*segments));

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		image->control_page = crashk_res.start;
		image->type = KEXEC_TYPE_CRASH;
	}
#endif

	/* Sanity check on segments */
	ret = sanity_check_segment_list(image);
	if (ret)
		goto out_free_image;

	/* Allocate control code buffer */
	image->control_code_page = kimage_alloc_control_pages(image, get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		pr_err("Could not allocate control_code_buffer\n");
		ret = -ENOMEM;
		goto out_free_image;
	}

	/* Allocate swap buffer if not in crash mode */
	if (!kexec_on_panic) {
		image->swap_page = kimage_alloc_control_pages(image, 0);
		if (!image->swap_page) {
			pr_err("Could not allocate swap buffer\n");
			ret = -ENOMEM;
			goto out_free_control_pages;
		}
	}

	*rimage = image;
	return 0;

out_free_control_pages:
	kimage_free_page_list(&image->control_pages);
out_free_image:
	kfree(image);
	return ret;
}

static int do_kexec_load(unsigned long entry, unsigned long nr_segments,
		struct kexec_segment *segments, unsigned long flags)
{
	struct kimage **dest_image, *image;
	int ret;

	/* Prevent concurrent crash kernel loads */
	if (!kexec_trylock())
		return -EBUSY;

#ifdef CONFIG_CRASH_DUMP
	/* If loading crash kernel, handle protection */
	if (flags & KEXEC_ON_CRASH) {
		dest_image = &kexec_crash_image;
		if (kexec_crash_image)
			arch_kexec_unprotect_crashkres();
	} else
#endif
		dest_image = &kexec_image;

	/* Uninstall existing image if no segments */
	if (nr_segments == 0) {
		kimage_free(xchg(dest_image, NULL));
		ret = 0;
		goto out_unlock;
	}

	/* Allocate and initialize kernel image */
	ret = kimage_alloc_init(&image, entry, nr_segments, segments, flags);
	if (ret)
		goto out_unlock;

	/* Prepare machine-specific kexec */
	ret = machine_kexec_prepare(image);
	if (ret)
		goto out_free_image;

	/* Load kernel segments into memory */
	for (unsigned long i = 0; i < nr_segments; i++) {
		ret = kimage_load_segment(image, &image->segment[i]);
		if (ret)
			goto out_free_image;
	}

	kimage_terminate(image);

	/* Post-load operations */
	ret = machine_kexec_post_load(image);
	if (!ret) {
		image = xchg(dest_image, image);
	}

out_free_image:
	kimage_free(image);
out_unlock:
	kexec_unlock();
	return ret;
}

SYSCALL_DEFINE4(kexec_load, unsigned long, entry, unsigned long, nr_segments,
		struct kexec_segment __user *, segments, unsigned long, flags)
{
	struct kexec_segment *ksegments;
	int result;

	/* Sanity check on kexec load */
	result = kexec_load_check(nr_segments, flags);
	if (result)
		return result;

	/* Validate architecture */
	if ((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH && 
	    (flags & KEXEC_ARCH_MASK) != KEXEC_ARCH_DEFAULT)
		return -EINVAL;

	/* Copy segments from userspace */
	ksegments = memdup_array_user(segments, nr_segments, sizeof(ksegments[0]));
	if (IS_ERR(ksegments))
		return PTR_ERR(ksegments);

	result = do_kexec_load(entry, nr_segments, ksegments, flags);
	kfree(ksegments);
	return result;
}
