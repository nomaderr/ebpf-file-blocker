# eBPF File Creation Blocker

**eBPF-based security module for blocking file creation in specific directories using Eunomia eBPF Runtime.**  
This program prevents files from being created inside `/etc/test/` using the Linux Security Module (LSM) with eBPF.

## Features
- Blocks file creation inside `/etc/test/`
- Uses eBPF LSM hooks for efficient security enforcement
- Minimal overhead compared to traditional kernel modules
- Compatible with **Eunomia eBPF Runtime**
- Logs blocked attempts using `bpf_printk`

## Installation & Compilation

### Prerequisites
- **Linux Kernel** with eBPF and BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- **Clang/LLVM** for compiling eBPF programs
- **Eunomia-bpf** installed ([GitHub](https://github.com/eunomia-bpf/eunomia-bpf))

### Compile and Load the eBPF Program
```sh
# Clone this repository
git clone https://github.com/YOUR_GITHUB_USERNAME/ebpf-block-file.git
cd ebpf-block-file

# Compile using Eunomia eBPF Compiler (ecc)
ecc block_file_create.c

# Load the eBPF program
ecli run package.json
```
### Try to create file in /etc/test for example with touch comand and you should get:
```
touch: cannot touch 'file': Operation not permitted
```
### Checking Logs
To monitor blocked file creation attempts, use:
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
The output should be similar to:
```
touch-2502    [007] ....1   161.355842: bpf_trace_printk: Blocked file creation in /etc/test: file
```

### License
This project is licensed under GPL-2.0.