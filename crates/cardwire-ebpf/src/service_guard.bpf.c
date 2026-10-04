/* SPDX-License-Identifier: GPL-3.0-only
 * Experimental service guard, explicitly loaded only by the VM tests so far.
 * Snapshot/role/ticket ABI is shared with cardwire-policy::service_roles.
 * Owner must retain every published executable/cgroup object until deactivation.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define CORE __attribute__((preserve_access_index))
#define CW_MAGIC 0x50535743
#define CW_VERSION 1
#define CW_ROLES 16
#define CW_DEVICES 16
struct super_block { unsigned int s_dev; } CORE;
struct inode { unsigned long i_ino; unsigned short i_mode; unsigned int i_rdev;
               struct super_block *i_sb; } CORE;
struct file { struct inode *f_inode; } CORE;
struct mm_struct { struct file *exe_file; } CORE;
typedef struct { unsigned int val; } kuid_t;
struct cred { kuid_t uid; kuid_t euid; } CORE;
struct task_struct { struct task_struct *group_leader; struct mm_struct *mm;
                     const struct cred *cred; } CORE;
struct role {
    __u64 incarnation, cgroup_id, executable_inode;
    __u32 executable_device, uid, access_mask, reserved;
};
struct snapshot {
    __u32 magic, version;
    __u64 generation;
    __u32 role_count, default_mask; /* devices any process may open */
    struct role roles[CW_ROLES];
};
struct inventory { __u32 count, reserved, devices[CW_DEVICES]; };
struct ticket { __u64 incarnation; __u32 role_index, reserved; };
_Static_assert(sizeof(struct role) == 40, "role ABI");
_Static_assert(sizeof(struct snapshot) == 664, "snapshot ABI");
_Static_assert(__builtin_offsetof(struct snapshot, roles) == 24, "roles offset");
_Static_assert(sizeof(struct inventory) == 72, "inventory ABI");
_Static_assert(sizeof(struct ticket) == 16, "ticket ABI");

struct inner_policy {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, __u32);
    __type(value, struct snapshot);
} CW_TEMPLATE SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct inner_policy);
} CW_ACTIVE SEC(".maps") = { .values = { &CW_TEMPLATE } };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, __u32);
    __type(value, struct inventory);
} CW_DEVICES_MAP SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct ticket);
} CW_ROLE_TASKS SEC(".maps");

static __always_inline struct snapshot *policy(void)
{
    __u32 zero = 0;
    void *inner = bpf_map_lookup_elem(&CW_ACTIVE, &zero);
    if (!inner) return 0;
    struct snapshot *s = bpf_map_lookup_elem(inner, &zero);
    if (!s || s->magic != CW_MAGIC || s->version != CW_VERSION || !s->generation ||
        s->role_count > CW_ROLES) return 0;
    return s;
}

static __always_inline int matches(struct task_struct *task, struct role *r)
{
    if (!r->incarnation || r->reserved || bpf_get_current_cgroup_id() != r->cgroup_id) return 0;
    const struct cred *c = task->cred;
    if (!c || c->uid.val != r->uid || c->euid.val != r->uid) return 0;
    struct mm_struct *mm = task->mm;
    if (!mm) return 0;
    struct file *exe = mm->exe_file;
    if (!exe) return 0;
    struct inode *i = exe->f_inode;
    if (!i || i->i_ino != r->executable_inode) return 0;
    struct super_block *sb = i->i_sb;
    return sb && sb->s_dev == r->executable_device;
}

SEC("tp_btf/sched_process_exec")
int service_exec(__u64 *ctx)
{
    struct task_struct *task = (void *)ctx[0];
    struct task_struct *leader = task->group_leader;
    if (!leader) return 0;
    bpf_task_storage_delete(&CW_ROLE_TASKS, leader);
    struct snapshot *s = policy();
    if (!s) return 0;
    for (__u32 n = 0; n < CW_ROLES; n++) {
        if (n >= s->role_count) break;
        struct role *r = &s->roles[n];
        if (!matches(task, r)) continue;
        struct ticket *t = bpf_task_storage_get(&CW_ROLE_TASKS, leader, 0,
                                               BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (t) { t->incarnation = r->incarnation; t->role_index = n; t->reserved = 0; }
        break;
    }
    return 0;
}

SEC("lsm/file_open")
int service_open(__u64 *ctx)
{
    int previous = (int)ctx[1];
    if (previous) return previous;
    struct file *file = (void *)ctx[0];
    struct inode *i = file->f_inode;
    if (!i || (i->i_mode & 0170000) != 0020000) return 0;
    __u32 zero = 0;
    struct inventory *inv = bpf_map_lookup_elem(&CW_DEVICES_MAP, &zero);
    if (!inv || !inv->count || inv->count > CW_DEVICES || inv->reserved) return -13;
    __u32 access = 0;
    for (__u32 n = 0; n < CW_DEVICES; n++) {
        if (n >= inv->count) break;
        if (i->i_rdev == inv->devices[n]) { access = 1u << n; break; }
    }
    if (!access) return 0;
    /* One immutable inner-map pointer for the whole decision, never two independently
     * published config/roles maps. No policy pointer means deny protected nodes. */
    struct snapshot *s = policy();
    if (!s) return -13;
    if (s->default_mask & access) return 0;
    struct task_struct *task = bpf_get_current_task_btf();
    struct task_struct *leader = task->group_leader;
    if (!leader) return -13;
    struct ticket *t = bpf_task_storage_get(&CW_ROLE_TASKS, leader, 0, 0);
    if (!t || t->reserved || t->role_index >= CW_ROLES || t->role_index >= s->role_count) return -13;
    struct role *r = &s->roles[t->role_index];
    if (t->incarnation != r->incarnation || !(r->access_mask & access) || !matches(task, r)) return -13;
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
