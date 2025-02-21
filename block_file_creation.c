// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define MAX_NAME_LEN 64

/**
 * Здесь указываем, какой путь «разрешить»: /etc/test
 * Если хотите другой путь (две компоненты),
 * например /var/log, то задайте:
 *   #define ALLOWED_PARENT "var"
 *   #define ALLOWED_CHILD  "log"
 */
#define ALLOWED_PARENT "etc"
#define ALLOWED_CHILD  "test"

/**
 * Простейшая функция сравнения строк (до MAX_NAME_LEN).
 * Возвращает true, если совпадают, иначе false.
 */
static __inline bool name_equals(const char *name, const char *pattern) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_NAME_LEN; i++) {
        if (name[i] != pattern[i])
            return false;
        if (name[i] == '\0')
            return true;  
    }
    return false;
}

/**
 * Хук LSM: inode_create — срабатывает при создании нового файла/каталога.
 * Блокируем всё, кроме /etc/test (или вашего пути, заданного выше).
 */
SEC("lsm/inode_create")
int BPF_PROG(block_all_except_my_path,
             struct inode *dir, struct dentry *dentry, umode_t mode)
{
    // начинаем с dentry вновь создаваемого объекта
    struct dentry *current = dentry;

#pragma unroll
    for (int depth = 0; depth < 20; depth++) {
        if (!current)
            break;

        // Считываем имя текущего dentry
        char current_name[MAX_NAME_LEN] = {};
        bpf_probe_read_kernel_str(current_name, sizeof(current_name),
                                  BPF_CORE_READ(current, d_name.name));

        // Шаг 1: проверяем, совпадает ли имя с ALLOWED_CHILD ("test")
        if (name_equals(current_name, ALLOWED_CHILD)) {
            // Берём родитель
            struct dentry *parent = BPF_CORE_READ(current, d_parent);
            if (!parent)
                break;

            // Считываем имя родителя
            char parent_name[MAX_NAME_LEN] = {};
            bpf_probe_read_kernel_str(parent_name, sizeof(parent_name),
                                      BPF_CORE_READ(parent, d_name.name));

            // Шаг 2: имя родителя должно быть ALLOWED_PARENT ("etc")
            if (name_equals(parent_name, ALLOWED_PARENT)) {
                // Шаг 3: проверяем, что это находится непосредственно под корнем.
                // Обычно корень узнаётся по parent->d_parent == parent (сам на себя)
                struct dentry *grandp = BPF_CORE_READ(parent, d_parent);
                if (grandp) {
                    struct dentry *ggp = BPF_CORE_READ(grandp, d_parent);
                    if (ggp == grandp) {
                        // Значит, это /etc/test => разрешаем создание
                        return 0;
                    }
                }
            }
        }

        // Переходим выше по дереву
        current = BPF_CORE_READ(current, d_parent);
    }

    // Если вышли из цикла — значит, наш путь не совпал => блокируем
    return -EPERM;
}
