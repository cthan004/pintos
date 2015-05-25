#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

//maxmimum length of of a command
#define CMD_MAX 1024
//maximum possible number of arguments
#define MAX_ARGS 128


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
