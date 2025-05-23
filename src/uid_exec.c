#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/version.h>


#define MAX_ALLOWED_UIDS 16 // только 16 юзеров могут запускать программы

static kuid_t allowed_user_ids[MAX_ALLOWED_UIDS]; // юзеры которым можно выполнять программы
static int allowed_uid_count = 0; 

static struct proc_dir_entry *proc_entry = NULL; // proc 

static asmlinkage long (*original_execve)(const char __user *, const char __user *const __user *, const char __user *const __user *); // указатель на execve

static asmlinkage long restricted_execve(const char __user *filename,
                                         const char __user *const __user *argv,
                                         const char __user *const __user *envp) { // execve проверяем есть ли в списке юзер или нет
    kuid_t uid = current_uid();

    for (int i = 0; i < allowed_uid_count; i++) {
        if (uid_eq(uid, allowed_user_ids[i])) {
            return original_execve(filename, argv, envp);
        }
    }

    printk(KERN_INFO "[uid_exec] Запуск заблокирован для UID: %u\n", __kuid_val(uid)); 
    return -EPERM;
}

static ssize_t proc_write_handler(struct file *file, const char __user *user_input, size_t len, loff_t *offset) { // proc/exec_allow
    char input_buffer[256];
    int parsed_uid, idx = 0;

    if (len >= sizeof(input_buffer))
        return -EINVAL;

    if (copy_from_user(input_buffer, user_input, len))
        return -EFAULT;

    input_buffer[len] = '\0';
    allowed_uid_count = 0;

    while (sscanf(input_buffer + idx, "%d", &parsed_uid) == 1 && allowed_uid_count < MAX_ALLOWED_UIDS) { // читаем юзеров и добавляем в список
        allowed_user_ids[allowed_uid_count++] = make_kuid(current_user_ns(), parsed_uid);
        while (input_buffer[idx] != '\0' && input_buffer[idx] != ' ') idx++;
        while (input_buffer[idx] == ' ') idx++;
    }

    printk(KERN_INFO "[uid_exec] Обновлён список разрешённых UID. Всего: %d\n", allowed_uid_count);
    return len;
}

static const struct file_operations proc_file_operations = {
    .owner = THIS_MODULE,
    .write = proc_write_handler,
};

static unsigned long **find_syscall_table(void); 
static unsigned long **syscall_table = NULL;

static int __init module_start(void) {// создаем модуль
    proc_entry = proc_create("exec_allow", 0666, NULL, &proc_file_operations);
    if (!proc_entry) {
        printk(KERN_ERR "[uid_exec] Не удалось создать /proc запись\n");
        return -ENOMEM;
    }

    syscall_table = find_syscall_table();
    if (!syscall_table)
        return -EINVAL;

    write_cr0(read_cr0() & (~0x10000));
    original_execve = (void *)syscall_table[__NR_execve];
    syscall_table[__NR_execve] = (unsigned long *)restricted_execve;
    write_cr0(read_cr0() | 0x10000);

    printk(KERN_INFO "[uid_exec] Модуль execve загружен\n");
    return 0;
}


static void __exit module_stop(void) { //выгружаем модуль 
    write_cr0(read_cr0() & (~0x10000));
    syscall_table[__NR_execve] = (unsigned long *)original_execve;
    write_cr0(read_cr0() | 0x10000);

    if (proc_entry)
        remove_proc_entry("exec_allow", NULL);

    printk(KERN_INFO "[uid_exec] Модуль execve выгружен\n");
}

module_init(module_start);
module_exit(module_stop);
