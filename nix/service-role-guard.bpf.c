/* SPDX-License-Identifier: GPL-3.0-only
 * Disposable-VM service-role candidate. Not loaded by the installed daemon.
 * Minimal CO-RE types keep task pointers typed for task-storage helpers.
 * Executable/cgroup objects must remain referenced by the test controller.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define CORE __attribute__((preserve_access_index))
struct super_block { unsigned int s_dev; } CORE;
struct inode {
    unsigned long i_ino;
    unsigned short i_mode;
    unsigned int i_rdev;
    struct super_block *i_sb;
} CORE;
struct file { struct inode *f_inode; } CORE;
struct mm_struct { struct file *exe_file; } CORE;
typedef struct { unsigned int val; } kuid_t;
struct cred { kuid_t uid; kuid_t euid; } CORE;
struct task_struct {
    struct task_struct *group_leader;
    struct mm_struct *mm;
    const struct cred *cred;
} CORE;

struct role_config {
    __u64 generation;
    __u64 cgroup_id;
    __u64 executable_inode;
    __u32 executable_device;
    __u32 uid;
    __u32 protected_rdev;
    __u32 active;
};
_Static_assert(sizeof(struct role_config) == 40, "role config ABI size");
_Static_assert(__builtin_offsetof(struct role_config, protected_rdev) == 32,
               "role config device ABI offset");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct role_config);
} VM_ROLE_CONFIG SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} VM_ROLE_CGROUP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} VM_ROLE_TASKS SEC(".maps");

static __always_inline struct role_config *config(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&VM_ROLE_CONFIG, &zero);
}

static __always_inline int matches(struct task_struct *task, struct role_config *rule)
{
    if (bpf_get_current_cgroup_id() != rule->cgroup_id ||
        bpf_current_task_under_cgroup(&VM_ROLE_CGROUP, 0) != 1)
        return 0;
    const struct cred *cred = task->cred;
    if (!cred || cred->uid.val != rule->uid || cred->euid.val != rule->uid)
        return 0;
    struct mm_struct *mm = task->mm;
    if (!mm)
        return 0;
    struct file *exe = mm->exe_file;
    if (!exe)
        return 0;
    struct inode *inode = exe->f_inode;
    if (!inode || inode->i_ino != rule->executable_inode)
        return 0;
    struct super_block *sb = inode->i_sb;
    return sb && sb->s_dev == rule->executable_device;
}

SEC("tp_btf/sched_process_exec")
int role_exec(__u64 *ctx)
{
    struct task_struct *task = (void *)ctx[0];
    struct task_struct *leader = task->group_leader;
    if (!leader)
        return 0;
    /* Exec, including exec from a non-leader, must invalidate old admission. */
    bpf_task_storage_delete(&VM_ROLE_TASKS, leader);
    struct role_config *rule = config();
    if (!rule || !rule->active || !matches(task, rule))
        return 0;
    __u64 *generation = bpf_task_storage_get(&VM_ROLE_TASKS, leader, 0,
                                           BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (generation)
        *generation = rule->generation;
    return 0;
}

SEC("lsm/file_open")
int role_open(__u64 *ctx)
{
    int previous = (int)ctx[1];
    if (previous)
        return previous;
    struct role_config *rule = config();
    if (!rule || !rule->active)
        return 0;
    struct file *file = (void *)ctx[0];
    struct inode *inode = file->f_inode;
    if (!inode || (inode->i_mode & 0170000) != 0020000 ||
        inode->i_rdev != rule->protected_rdev)
        return 0;
    struct task_struct *task = bpf_get_current_task_btf();
    struct task_struct *leader = task->group_leader;
    if (!leader)
        return -13;
    __u64 *generation = bpf_task_storage_get(&VM_ROLE_TASKS, leader, 0, 0);
    if (!generation || *generation != rule->generation || !matches(task, rule))
        return -13;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
