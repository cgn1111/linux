// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/panic.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * This function is used throughout the kernel (including mm and fs)
 * to indicate a major problem.
 */
#include <linux/debug_locks.h>
#include <linux/sched/debug.h>
#include <linux/interrupt.h>
#include <linux/kgdb.h>
#include <linux/kmsg_dump.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/vt_kern.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/ftrace.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/panic_notifier.h>
#include <linux/sched.h>
#include <linux/string_helpers.h>
#include <linux/sysrq.h>
#include <linux/init.h>
#include <linux/nmi.h>
#include <linux/console.h>
#include <linux/bug.h>
#include <linux/ratelimit.h>
#include <linux/debugfs.h>
#include <linux/sysfs.h>
#include <linux/context_tracking.h>
#include <linux/seq_buf.h>
#include <trace/events/error_report.h>
#include <asm/sections.h>

#define PANIC_TIMER_STEP 100
#define PANIC_BLINK_SPD 18

#ifdef CONFIG_SMP
static unsigned int __read_mostly sysctl_oops_all_cpu_backtrace;
#else
#define sysctl_oops_all_cpu_backtrace 0
#endif /* CONFIG_SMP */

int panic_on_oops = CONFIG_PANIC_ON_OOPS_VALUE;
static unsigned long tainted_mask = IS_ENABLED(CONFIG_RANDSTRUCT) ? (1 << TAINT_RANDSTRUCT) : 0;
static int pause_on_oops;
static int pause_on_oops_flag;
static DEFINE_SPINLOCK(pause_on_oops_lock);
bool crash_kexec_post_notifiers;
int panic_on_warn __read_mostly;
unsigned long panic_on_taint;
bool panic_on_taint_nousertaint = false;
static unsigned int warn_limit __read_mostly;

bool panic_triggering_all_cpu_backtrace;

int panic_timeout = CONFIG_PANIC_TIMEOUT;
EXPORT_SYMBOL_GPL(panic_timeout);

#define PANIC_PRINT_TASK_INFO       0x00000001
#define PANIC_PRINT_MEM_INFO        0x00000002
#define PANIC_PRINT_TIMER_INFO      0x00000004
#define PANIC_PRINT_LOCK_INFO       0x00000008
#define PANIC_PRINT_FTRACE_INFO     0x00000010
#define PANIC_PRINT_ALL_PRINTK_MSG  0x00000020
#define PANIC_PRINT_ALL_CPU_BT      0x00000040
#define PANIC_PRINT_BLOCKED_TASKS   0x00000080
unsigned long panic_print;

ATOMIC_NOTIFIER_HEAD(panic_notifier_list);
EXPORT_SYMBOL(panic_notifier_list);

#ifdef CONFIG_SYSCTL
static struct ctl_table kern_panic_table[] = {
#ifdef CONFIG_SMP
    {
        .procname       = "oops_all_cpu_backtrace",
        .data           = &sysctl_oops_all_cpu_backtrace,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec_minmax,
        .extra1         = SYSCTL_ZERO,
        .extra2         = SYSCTL_ONE,
    },
#endif
    {
        .procname       = "warn_limit",
        .data           = &warn_limit,
        .maxlen         = sizeof(warn_limit),
        .mode           = 0644,
        .proc_handler   = proc_douintvec,
    },
};

static __init int kernel_panic_sysctls_init(void)
{
    register_sysctl_init("kernel", kern_panic_table);
    return 0;
}
late_initcall(kernel_panic_sysctls_init);
#endif

static atomic_t warn_count = ATOMIC_INIT(0);

#ifdef CONFIG_SYSFS
static ssize_t warn_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *page)
{
    return sysfs_emit(page, "%d\n", atomic_read(&warn_count));
}

static struct kobj_attribute warn_count_attr = __ATTR_RO(warn_count);

static __init int kernel_panic_sysfs_init(void)
{
    sysfs_add_file_to_group(kernel_kobj, &warn_count_attr.attr, NULL);
    return 0;
}
late_initcall(kernel_panic_sysfs_init);
#endif

static long no_blink(int state)
{
    return 0;
}

long (*panic_blink)(int state) = no_blink;
EXPORT_SYMBOL(panic_blink);

void __weak __noreturn panic_smp_self_stop(void)
{
    while (1)
        cpu_relax();
}

void __weak __noreturn nmi_panic_self_stop(struct pt_regs *regs)
{
    panic_smp_self_stop();
}

void __weak crash_smp_send_stop(void)
{
    static int cpus_stopped;

    if (cpus_stopped)
        return;

    smp_send_stop();
    cpus_stopped = 1;
}

atomic_t panic_cpu = ATOMIC_INIT(PANIC_CPU_INVALID);

void nmi_panic(struct pt_regs *regs, const char *msg)
{
    int old_cpu, this_cpu;

    old_cpu = PANIC_CPU_INVALID;
    this_cpu = raw_smp_processor_id();

    if (atomic_try_cmpxchg(&panic_cpu, &old_cpu, this_cpu))
        panic("%s", msg);
    else if (old_cpu != this_cpu)
        nmi_panic_self_stop(regs);
}
EXPORT_SYMBOL(nmi_panic);

static void panic_print_sys_info(bool console_flush)
{
    if (console_flush) {
        if (panic_print & PANIC_PRINT_ALL_PRINTK_MSG)
            console_flush_on_panic(CONSOLE_REPLAY_ALL);
        return;
    }

    if (panic_print & PANIC_PRINT_TASK_INFO)
        show_state();

    if (panic_print & PANIC_PRINT_MEM_INFO)
        show_mem();

    if (panic_print & PANIC_PRINT_TIMER_INFO)
        sysrq_timer_list_show();

    if (panic_print & PANIC_PRINT_LOCK_INFO)
        debug_show_all_locks();

    if (panic_print & PANIC_PRINT_FTRACE_INFO)
        ftrace_dump(DUMP_ALL);

    if (panic_print & PANIC_PRINT_BLOCKED_TASKS)
        show_state_filter(TASK_UNINTERRUPTIBLE);
}

void check_panic_on_warn(const char *origin)
{
    unsigned int limit;

    if (panic_on_warn)
        panic("%s: panic_on_warn set ...\n", origin);

    limit = READ_ONCE(warn_limit);
    if (atomic_inc_return(&warn_count) >= limit && limit)
        panic("%s: system warned too often (kernel.warn_limit is %d)", origin, limit);
}

static void panic_other_cpus_shutdown(bool crash_kexec)
{
    if (panic_print & PANIC_PRINT_ALL_CPU_BT) {
        panic_triggering_all_cpu_backtrace = true;
        trigger_all_cpu_backtrace();
        panic_triggering_all_cpu_backtrace = false;
    }

    if (!crash_kexec)
        smp_send_stop();
    else
        crash_smp_send_stop();
}

void panic(const char *fmt, ...)
{
    static char buf[1024];
    va_list args;
    long i, i_next = 0, len;
    int state = 0;
    int old_cpu, this_cpu;
    bool _crash_kexec_post_notifiers = crash_kexec_post_notifiers;

    if (panic_on_warn) {
        panic_on_warn = 0;
    }

    local_irq_disable();
    preempt_disable_notrace();

    old_cpu = PANIC_CPU_INVALID;
    this_cpu = raw_smp_processor_id();

    if (atomic_try_cmpxchg(&panic_cpu, &old_cpu, this_cpu)) {
        // go ahead
    } else if (old_cpu != this_cpu) {
        panic_smp_self_stop();
    }

    console_verbose();
    bust_spinlocks(1);
    va_start(args, fmt);
    len = vscnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len && buf[len - 1] == '\n')
        buf[len - 1] = '\0';

    pr_emerg("Kernel panic - not syncing: %s\n", buf);
#ifdef CONFIG_DEBUG_BUGVERBOSE
    if (!test_taint(TAINT_DIE) && oops_in_progress <= 1)
        dump_stack();
#endif

    kgdb_panic(buf);

    if (!_crash_kexec_post_notifiers)
        __crash_kexec(NULL);

    panic_other_cpus_shutdown(_crash_kexec_post_notifiers);
    printk_legacy_allow_panic_sync();

    atomic_notifier_call_chain(&panic_notifier_list, 0, buf);
    panic_print_sys_info(false);
    kmsg_dump_desc(KMSG_DUMP_PANIC, buf);

    if (_crash_kexec_post_notifiers)
        __crash_kexec(NULL);

    console_unblank();

    debug_locks_off();
    console_flush_on_panic(CONSOLE_FLUSH_PENDING);
    panic_print_sys_info(true);

    if (panic_timeout > 0) {
        pr_emerg("Rebooting in %d seconds..\n", panic_timeout);

        for (i = 0
