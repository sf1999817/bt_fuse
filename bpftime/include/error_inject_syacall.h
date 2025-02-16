// error_inject_syscall.h

#ifndef ERROR_INJECT_SYSCALL_H
#define ERROR_INJECT_SYSCALL_H

#define MAX_DATA_LEN 1024
struct event {
    char pathname[256];
    int mode;
    char command[50];
    size_t size;
    char data[MAX_DATA_LEN];
};

#endif // ERROR_INJECT_SYSCALL_H
