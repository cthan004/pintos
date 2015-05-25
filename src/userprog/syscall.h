#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define CODE_SEG_BOTTOM 0x08048000

void syscall_init (void);
char *copy_in_string (const char *us);
void copy_in (void *dst_, const void *usrc_, int size);

#endif /* userprog/syscall.h */
