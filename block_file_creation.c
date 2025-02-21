// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

#define MAX_NAME_LEN 64


static __inline bool name_equals(const char *name, const char *pattern) {
    for (int i = 0; i < MAX_NAME_LEN; i++) {
        if (name[i] != pattern[i])
            return false;
        if (name[i] == '\0')
            return true;  
    }
    return false;
}


SEC("lsm/inode_create")
int BPF_PROG(block_all_except_etc_test,
             struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct dentry *current = dentry;

#pragma unroll
    for (int depth = 0; depth < 20; depth++) {
        if (!current)
            break;

        char current_name[MAX_NAME_LEN] = {};
        bpf_probe_read_kernel_str(current_name, sizeof(current_name),
                                  BPF_CORE_READ(current, d_name.name));

        if (name_equals(current_name, "test")) {
            struct dentry *parent = BPF_CORE_READ(current, d_parent);
            if (!parent)
                break;

            char parent_name[MAX_NAME_LEN] = {};
            bpf_probe_read_kernel_str(parent_name, sizeof(parent_name),
                                      BPF_CORE_READ(parent, d_name.name));

            if (name_equals(parent_name, "etc")) {
                struct dentry *grandp = BPF_CORE_READ(parent, d_parent);
                if (grandp) {
                    struct dentry *ggp = BPF_CORE_READ(grandp, d_parent);
                    if (ggp == grandp) {
                        
                        return 0;  
                    }
                }
            }
        }

        current = BPF_CORE_READ(current, d_parent);
    }

    return -EPERM;
}
