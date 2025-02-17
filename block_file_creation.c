// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Error code returned when an operation is prohibited (EPERM - Operation not permitted).
#define EPERM 1

// Maximum length of file or directory name used for buffers.
#define MAX_NAME_LEN 64

/**
* @brief eBPF program that uses the inode_create LSM hook to block
* file creation in a specific directory (/etc/test).
*
* @param dir Pointer to the inode of the parent directory where the file is being created.
* @param dentry Pointer to a dentry structure representing the file being created.
* @param mode Access rights of the file being created.
*
* @return 0 if the operation is allowed, -EPERM if file creation is prohibited.
*
* This eBPF hook is executed when an attempt is made to create a new file in the file system.
* It checks if the file is in the prohibited `/etc/test` directory,
* and if so, prevents its creation.
*/
SEC("lsm/inode_create")
int BPF_PROG(block_file_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    
    // Buffers for storing the names of the file being created and its parent directory.
    char name[MAX_NAME_LEN];
    char parent_name[MAX_NAME_LEN];

    // Extract the name of the file being created from the dentry structure.
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

    // Read the name of the file being created into the name variable.
    bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);

    // Read the name of the parent directory in which the file is created.
    bpf_probe_read_kernel_str(parent_name, sizeof(parent_name), BPF_CORE_READ(parent, d_name.name));

    /**
    * Check if a file is created in the "test" directory.
    * The directory name is checked character by character, since eBPF does not allow
    * to use standard string functions from <string.h>.
    */
    if (parent_name[0] == 't' && parent_name[1] == 'e' &&
        parent_name[2] == 's' && parent_name[3] == 't' && parent_name[4] == '\0') {
        
        // Get a pointer to the parent directory (grandparent), that is /etc/
        struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
        char grandparent_name[MAX_NAME_LEN];

        // Read parent name dir into grandparent_name variable
        bpf_probe_read_kernel_str(grandparent_name, sizeof(grandparent_name), BPF_CORE_READ(grandparent, d_name.name));

        /**
        * Check if grandparent is "/etc/".
        * If the parent directory is "test" and its parent is "etc",
        * then the file path is "/etc/test/".
        */
        if (grandparent_name[0] == 'e' && grandparent_name[1] == 't' &&
            grandparent_name[2] == 'c' && grandparent_name[3] == '\0') {

            // Output the message to bpf_printk (can be viewed via trace_pipe).
            bpf_printk("Blocked file creation in /etc/test: %s\n", name);

            // Block file creation and returning "Operation not permitted" error.
            return -EPERM;
        }
    }

    // Allow the operation if the path does not match the forbidden one.
    return 0;
}